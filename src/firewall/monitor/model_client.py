"""
ModelClient protocol and strict monitor output parser (C4) for AI Agent Permission Firewall.

Enforces:
- D-26: LLM monitor output parsed by exact match on strict JSON; anything else => UNKNOWN.
- D-37: Deep-monitor UNKNOWN, timeout, exception, or malformed output
  maps to MonitorVerdict.UNKNOWN.
- Fail-closed error normalization (INV-04).
- Information barrier and offline deterministic execution (INV-08, OQ-12).

Canonical Output Schema:
{
    "verdict": "BENIGN" | "SUSPICIOUS" | "UNKNOWN",
    "confidence": float,  # in [0.0, 1.0], finite, non-boolean
    "reasoning": str
}
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from firewall.contracts.enums import MonitorVerdict, ScoreKind
from firewall.contracts.models import MonitorAssessment


class MonitorOutputParseError(ValueError):
    """Raised when monitor output does not strictly conform to canonical JSON schema."""
    pass


@dataclass(frozen=True)
class StrictMonitorOutput:
    """Validated structured output from monitor."""
    verdict: MonitorVerdict
    confidence: float
    reasoning: str


def parse_monitor_output(raw_output: str) -> StrictMonitorOutput:
    """
    Strictly parse and validate raw monitor response according to D-26 and INV-04.

    Rules:
    - Must be a single valid JSON object.
    - Exact keys required: {"verdict", "confidence", "reasoning"}. No extra keys allowed.
    - "verdict": Must be one of "BENIGN", "SUSPICIOUS", "UNKNOWN".
    - "confidence": Must be a finite float/int in [0.0, 1.0]. Booleans are strictly rejected.
    - "reasoning": Must be a string.
    - No heuristic parsing, no prose extraction, no last-token fallback.

    Raises:
        MonitorOutputParseError: If any rule is violated.
    """
    if not isinstance(raw_output, str):
        msg = f"Raw output must be a string, got {type(raw_output).__name__}"
        raise MonitorOutputParseError(msg)

    stripped = raw_output.strip()
    if not stripped:
        raise MonitorOutputParseError("Raw output is empty or whitespace only")

    try:
        data = json.loads(stripped)
    except Exception as e:
        raise MonitorOutputParseError(f"Malformed JSON: {e}") from e

    if not isinstance(data, dict):
        raise MonitorOutputParseError(f"Expected JSON object, got {type(data).__name__}")

    allowed_keys = {"verdict", "confidence", "reasoning"}
    actual_keys = set(data.keys())

    if actual_keys != allowed_keys:
        missing = allowed_keys - actual_keys
        extra = actual_keys - allowed_keys
        err_parts = []
        if missing:
            err_parts.append(f"missing required keys: {sorted(missing)}")
        if extra:
            err_parts.append(f"unexpected extra keys: {sorted(extra)}")
        raise MonitorOutputParseError(f"Schema key mismatch: {', '.join(err_parts)}")

    # 1. Validate verdict
    raw_verdict = data["verdict"]
    if not isinstance(raw_verdict, str):
        msg = f"'verdict' must be a string, got {type(raw_verdict).__name__}"
        raise MonitorOutputParseError(msg)

    valid_verdicts = {
        "BENIGN": MonitorVerdict.BENIGN,
        "SUSPICIOUS": MonitorVerdict.SUSPICIOUS,
        "UNKNOWN": MonitorVerdict.UNKNOWN,
    }
    if raw_verdict not in valid_verdicts:
        raise MonitorOutputParseError(
            f"Invalid verdict '{raw_verdict}'; must be one of {sorted(valid_verdicts.keys())}"
        )
    verdict = valid_verdicts[raw_verdict]

    # 2. Validate confidence
    raw_conf = data["confidence"]
    # In Python, bool is a subclass of int (isinstance(True, int) is True). Must reject explicitly!
    if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
        val_type = type(raw_conf).__name__
        raise MonitorOutputParseError(f"'confidence' must be numeric float/int, got {val_type}")

    conf_float = float(raw_conf)
    if math.isnan(conf_float) or math.isinf(conf_float):
        raise MonitorOutputParseError(f"'confidence' must be finite, got {conf_float}")

    if not (0.0 <= conf_float <= 1.0):
        raise MonitorOutputParseError(f"'confidence' out of bounds [0.0, 1.0]: {conf_float}")

    # 3. Validate reasoning
    raw_reasoning = data["reasoning"]
    if not isinstance(raw_reasoning, str):
        val_type = type(raw_reasoning).__name__
        raise MonitorOutputParseError(f"'reasoning' must be a string, got {val_type}")

    return StrictMonitorOutput(
        verdict=verdict,
        confidence=conf_float,
        reasoning=raw_reasoning,
    )


def normalize_to_unknown_assessment(
    error_msg: str,
    monitor_version: str,
    model_id: Optional[str] = None,
    prompt_hash: Optional[str] = None,
    raw_output: Optional[str] = None,
    latency_ms: float = 0.0,
) -> MonitorAssessment:
    """
    Creates a fail-closed MonitorAssessment with verdict=UNKNOWN (D-37, INV-04).
    """
    return MonitorAssessment(
        verdict=MonitorVerdict.UNKNOWN,
        score=None,
        score_kind=ScoreKind.NONE,
        rationale=None,
        raw_output=raw_output,
        model_id=model_id,
        prompt_hash=prompt_hash,
        monitor_version=monitor_version,
        latency_ms=latency_ms,
        error=error_msg,
    )


@runtime_checkable
class ModelClient(Protocol):
    """
    Protocol for offline or hosted LLM/SLM model clients (C4).
    """

    model_id: str

    def complete(
        self,
        prompt: str,
        *,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        timeout_ms: Optional[int] = None,
    ) -> str:
        """
        Submit prompt to model and return raw text response.
        Must raise TimeoutError on timeout, or Exception on failure.
        """
        ...


class DeterministicMockModelClient:
    """
    Deterministic offline model client for testing and verification without live APIs.
    Records all calls for verification of information barriers and canary leakage.
    """

    def __init__(
        self,
        model_id: str = "deterministic_mock_v1",
        default_response: Optional[str] = None,
        default_verdict: Optional[MonitorVerdict] = None,
        default_confidence: float = 0.95,
        default_reasoning: str = "Mock analysis",
        responses_by_pattern: Optional[Dict[str, str]] = None,
        simulate_timeout: bool = False,
        simulate_exception: Optional[Exception] = None,
    ) -> None:
        self.model_id = model_id
        if default_response is not None:
            self.default_response = default_response
        elif default_verdict is not None:
            self.default_response = json.dumps({
                "verdict": default_verdict.value,
                "confidence": default_confidence,
                "reasoning": default_reasoning,
            })
        else:
            self.default_response = (
                '{"verdict": "BENIGN", "confidence": 0.95, "reasoning": "Mock analysis"}'
            )
        self.responses_by_pattern = (
            responses_by_pattern if responses_by_pattern is not None else {}
        )
        self.simulate_timeout = simulate_timeout
        self.simulate_exception = simulate_exception
        self.calls: List[Dict[str, Any]] = []

    def complete(
        self,
        prompt: str,
        *,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        timeout_ms: Optional[int] = None,
    ) -> str:
        self.calls.append({
            "prompt": prompt,
            "system_prompt": system_prompt,
            "temperature": temperature,
            "timeout_ms": timeout_ms,
        })

        if self.simulate_timeout:
            raise TimeoutError("Simulated client timeout exceeded")

        if self.simulate_exception is not None:
            raise self.simulate_exception

        for pattern, resp in self.responses_by_pattern.items():
            if pattern in prompt:
                return resp

        return self.default_response

    @property
    def history(self) -> List[Dict[str, Any]]:
        return self.calls

    def set_canned_response(self, pattern: str, response: str) -> None:
        self.responses_by_pattern[pattern] = response

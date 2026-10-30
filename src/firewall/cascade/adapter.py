"""
Cascade Adapter connecting rejection-cascade monitors to the AASF firewall decision flow.
Source: 05_TECHNICAL_SPEC.md §9, 06_EXPERIMENT_PROTOCOL.md §2,
        01_THREAT_MODEL.md (INV-03, INV-04, INV-08)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Union
from unittest.mock import Mock

from firewall.contracts.enums import (
    Decision,
    MonitorVerdict,
    PolicyVerdict,
)
from firewall.contracts.hashing import compute_action_hash
from firewall.contracts.models import (
    ActionRequest,
    CanonicalAction,
    MonitorAssessment,
    MonitorView,
    PolicyResult,
)

logger = logging.getLogger(__name__)


class CascadeFailureReason(str, Enum):
    """Structured failure reasons recorded for REVIEW escalations."""

    MONITOR_UNKNOWN = "MONITOR_UNKNOWN"
    MONITOR_TIMEOUT = "MONITOR_TIMEOUT"
    MONITOR_EXCEPTION = "MONITOR_EXCEPTION"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    MALFORMED_JSON = "MALFORMED_JSON"
    NO_MONITOR_CONFIGURED = "NO_MONITOR_CONFIGURED"


@dataclass(frozen=True)
class CascadeDecision:
    """
    Typed result returned by CascadeAdapter.decide().
    Encapsulates the final Decision, human-readable reason, structured reason codes,
    underlying policy and monitor verdicts, and any error details.
    Supports equality checks against Decision enums and tuple unpacking.
    """

    decision: Decision
    reason: str
    reason_codes: list[str] = field(default_factory=list)
    policy_verdict: PolicyVerdict = PolicyVerdict.UNDETERMINED
    monitor_verdict: MonitorVerdict = MonitorVerdict.NOT_CONSULTED
    error: Optional[str] = None
    raw_output: Optional[str] = None

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Decision):
            return self.decision == other
        if isinstance(other, str):
            return self.decision.value == other or self.decision == other
        if isinstance(other, CascadeDecision):
            return (
                self.decision == other.decision
                and self.reason == other.reason
                and self.reason_codes == other.reason_codes
            )
        return False

    def __iter__(self) -> Any:
        """Enable tuple unpacking: decision, reason_codes = adapter.decide(...)"""
        return iter((self.decision, self.reason_codes))


class CascadeAdapter:
    """
    Adapter bridging a rejection-cascade monitor into the AASF firewall decision pipeline.

    Enforces core firewall security invariants:
    - Hard policy prohibitions always dominate (PROHIBIT -> DENY, INV-03).
    - Unambiguous policy permits are respected (PERMIT -> ALLOW).
    - Incomplete evidence triggers human review (EVIDENCE_MISSING -> REVIEW, INV-04).
    - Cascade monitor is only consulted when policy is UNDETERMINED.
    - All monitor failures, timeouts, exceptions, malformed outputs, and UNKNOWN verdicts
      fail-closed to REVIEW with structured error attribution (INV-04, D-37).
    - An ALLOW decision is NEVER returned after a monitor failure.
    """

    monitor_id: str = "cascade_adapter"
    version: str = "0.1.0"

    def __init__(
        self,
        monitor: Optional[Any] = None,
        *,
        default_timeout_ms: Optional[int] = None,
    ) -> None:
        self.monitor = monitor
        self.default_timeout_ms = default_timeout_ms

    def decide(
        self,
        policy_verdict: Union[PolicyVerdict, PolicyResult, str],
        action: Optional[
            Union[ActionRequest, CanonicalAction, MonitorView, dict[str, Any], str]
        ] = None,
        *,
        monitor: Optional[Any] = None,
        view: Optional[MonitorView] = None,
        tool: Optional[str] = None,
        arguments: Optional[dict[str, Any]] = None,
        timeout_ms: Optional[int] = None,
        matched_rules: Optional[list[str]] = None,
        missing_fields: Optional[list[str]] = None,
    ) -> CascadeDecision:
        """
        Evaluate a request given a policy verdict and optional action context.

        Required behavior:
        - If policy verdict is PROHIBIT, return DENY.
        - If policy verdict is PERMIT, return ALLOW.
        - If policy verdict is EVIDENCE_MISSING, return REVIEW.
        - If policy verdict is UNDETERMINED, call the cascade monitor.
        - If the cascade monitor returns a valid decision, return that decision.
        - If the cascade monitor returns UNKNOWN, times out, raises an exception,
          or returns malformed output, return REVIEW.
        - Never return ALLOW after a monitor failure.
        - Record a structured failure reason for REVIEW escalation.
        """
        # 1. Normalize policy verdict input
        p_verdict, p_rules, p_missing = self._normalize_policy_verdict(
            policy_verdict, matched_rules, missing_fields
        )

        # 2. PROHIBIT supremacy: hard policy block dominates unconditionally (INV-03)
        if p_verdict == PolicyVerdict.PROHIBIT:
            reasons = [f"POLICY_PROHIBIT:{r}" for r in p_rules] if p_rules else ["POLICY_PROHIBIT"]
            return CascadeDecision(
                decision=Decision.DENY,
                reason="POLICY_PROHIBIT",
                reason_codes=reasons,
                policy_verdict=PolicyVerdict.PROHIBIT,
                monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            )

        # 3. Policy permit: authorize execution
        if p_verdict == PolicyVerdict.PERMIT:
            reasons = [f"POLICY_PERMIT:{r}" for r in p_rules] if p_rules else ["POLICY_PERMIT"]
            return CascadeDecision(
                decision=Decision.ALLOW,
                reason="POLICY_PERMIT",
                reason_codes=reasons,
                policy_verdict=PolicyVerdict.PERMIT,
                monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            )

        # 4. Incomplete evidence: fail-closed to REVIEW (INV-04)
        if p_verdict == PolicyVerdict.EVIDENCE_MISSING:
            missing_str = ",".join(p_missing) if p_missing else ""
            reason = f"EVIDENCE_MISSING:{missing_str}" if missing_str else "EVIDENCE_MISSING"
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason="EVIDENCE_MISSING",
                reason_codes=[reason],
                policy_verdict=PolicyVerdict.EVIDENCE_MISSING,
                monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            )

        # 5. Policy UNDETERMINED: consult the cascade monitor
        if p_verdict == PolicyVerdict.UNDETERMINED:
            active_monitor = monitor if monitor is not None else self.monitor
            if active_monitor is None:
                return CascadeDecision(
                    decision=Decision.REVIEW,
                    reason=CascadeFailureReason.NO_MONITOR_CONFIGURED.value,
                    reason_codes=[
                        CascadeFailureReason.NO_MONITOR_CONFIGURED.value,
                        CascadeFailureReason.MONITOR_UNKNOWN.value,
                    ],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    error="No cascade monitor configured to resolve UNDETERMINED policy verdict",
                )

            effective_timeout = timeout_ms if timeout_ms is not None else self.default_timeout_ms
            return self._call_and_evaluate_monitor(
                active_monitor,
                action=action,
                view=view,
                tool=tool,
                arguments=arguments,
                timeout_ms=effective_timeout,
            )

        # Catch-all unexpected policy verdict -> fail-closed to DENY
        return CascadeDecision(
            decision=Decision.DENY,
            reason="UNEXPECTED_POLICY_VERDICT",
            reason_codes=["UNEXPECTED_POLICY_VERDICT", str(p_verdict)],
            policy_verdict=p_verdict,
            monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            error=f"Unrecognized policy verdict: {p_verdict}",
        )

    evaluate = decide

    def assess(
        self,
        view: MonitorView,
        *,
        timeout_ms: Optional[int] = None,
    ) -> MonitorAssessment:
        """
        Implements the Monitor protocol so CascadeAdapter can be plugged directly
        into FirewallCore as an advisory monitor.
        """
        decision_result = self.decide(
            PolicyVerdict.UNDETERMINED,
            view=view,
            timeout_ms=timeout_ms,
        )

        score = 0.0 if decision_result.decision == Decision.ALLOW else 1.0
        return MonitorAssessment(
            verdict=decision_result.monitor_verdict,
            score=score,
            rationale=decision_result.reason,
            raw_output=decision_result.raw_output,
            monitor_version=self.version,
            error=decision_result.error,
        )

    def _normalize_policy_verdict(
        self,
        policy_verdict: Union[PolicyVerdict, PolicyResult, str],
        matched_rules: Optional[list[str]],
        missing_fields: Optional[list[str]],
    ) -> tuple[PolicyVerdict, list[str], list[str]]:
        rules = matched_rules or []
        missing = missing_fields or []

        if isinstance(policy_verdict, PolicyResult):
            return (
                policy_verdict.verdict,
                policy_verdict.matched_rules,
                policy_verdict.missing_fields,
            )

        if isinstance(policy_verdict, PolicyVerdict):
            return policy_verdict, rules, missing

        if isinstance(policy_verdict, str):
            clean_str = policy_verdict.strip().upper()
            try:
                return PolicyVerdict(clean_str), rules, missing
            except ValueError:
                logger.warning("Unrecognized policy verdict string: %s", policy_verdict)
                return PolicyVerdict.UNDETERMINED, rules, missing

        return PolicyVerdict.UNDETERMINED, rules, missing

    def _call_and_evaluate_monitor(
        self,
        monitor: Any,
        *,
        action: Optional[Any],
        view: Optional[MonitorView],
        tool: Optional[str],
        arguments: Optional[dict[str, Any]],
        timeout_ms: Optional[int],
    ) -> CascadeDecision:
        try:
            raw_response = self._invoke_monitor(
                monitor,
                action=action,
                view=view,
                tool=tool,
                arguments=arguments,
                timeout_ms=timeout_ms,
            )
        except TimeoutError as te:
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=CascadeFailureReason.MONITOR_TIMEOUT.value,
                reason_codes=[CascadeFailureReason.MONITOR_TIMEOUT.value, f"TIMEOUT:{te}"],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                error=f"TimeoutError: {te}",
            )
        except Exception as exc:
            exc_name = type(exc).__name__
            if "timeout" in exc_name.lower():
                reason_code = CascadeFailureReason.MONITOR_TIMEOUT.value
            else:
                reason_code = CascadeFailureReason.MONITOR_EXCEPTION.value

            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=reason_code,
                reason_codes=[reason_code, f"{exc_name}:{exc}"],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                error=f"{exc_name}: {exc}",
            )

        return self._parse_monitor_response(raw_response)

    def _invoke_monitor(
        self,
        monitor: Any,
        *,
        action: Optional[Any],
        view: Optional[MonitorView],
        tool: Optional[str],
        arguments: Optional[dict[str, Any]],
        timeout_ms: Optional[int],
    ) -> Any:
        effective_view = (
            view if view is not None else self._build_default_view(action, tool, arguments)
        )

        # 1. Real class with assess method (e.g. Monitor implementations, not raw mocks)
        if hasattr(type(monitor), "assess") and not issubclass(type(monitor), Mock):
            try:
                return monitor.assess(effective_view, timeout_ms=timeout_ms)
            except TypeError:
                return monitor.assess(effective_view)

        # 2. Callable monitor (e.g. lambda, function, or MagicMock configured with return_value)
        if callable(monitor):
            res = None
            try:
                res = monitor(effective_view)
            except TypeError:
                try:
                    res = monitor(tool=tool, arguments=arguments)
                except TypeError:
                    try:
                        res = monitor()
                    except TypeError:
                        res = None

            # If calling the callable returned a concrete non-Mock value, return it
            if res is not None and not isinstance(res, Mock):
                return res

            # If calling directly returned a Mock, check if monitor.assess was configured
            if hasattr(monitor, "assess") and callable(monitor.assess):
                try:
                    assess_res = monitor.assess(effective_view, timeout_ms=timeout_ms)
                except TypeError:
                    assess_res = monitor.assess(effective_view)

                if not isinstance(assess_res, Mock):
                    return assess_res

            # Return whichever was obtained if non-empty
            if res is not None:
                return res

        # 3. Assess method on mock or object
        if hasattr(monitor, "assess") and callable(monitor.assess):
            try:
                return monitor.assess(effective_view, timeout_ms=timeout_ms)
            except TypeError:
                return monitor.assess(effective_view)

        # 4. Monitor with evaluate(...)
        if hasattr(monitor, "evaluate") and callable(monitor.evaluate):
            try:
                return monitor.evaluate(tool=tool, arguments=arguments)
            except TypeError:
                return monitor.evaluate(effective_view)

        # 5. Monitor with decide(...)
        if hasattr(monitor, "decide") and callable(monitor.decide):
            try:
                return monitor.decide(effective_view)
            except TypeError:
                return monitor.decide(tool=tool, arguments=arguments)

        raise TypeError(
            f"Monitor of type {type(monitor).__name__} does not support assess, "
            "evaluate, or callable invocation"
        )

    def _parse_monitor_response(self, raw: Any) -> CascadeDecision:
        # A. Response is MonitorAssessment
        if isinstance(raw, MonitorAssessment):
            if raw.verdict == MonitorVerdict.UNKNOWN:
                error_upper = (raw.error or "").upper()
                if "TIMEOUT" in error_upper:
                    reason_code = CascadeFailureReason.MONITOR_TIMEOUT.value
                elif "EXCEPTION" in error_upper:
                    reason_code = CascadeFailureReason.MONITOR_EXCEPTION.value
                elif "JSON" in error_upper or "PARSE" in error_upper:
                    reason_code = CascadeFailureReason.MALFORMED_OUTPUT.value
                else:
                    reason_code = CascadeFailureReason.MONITOR_UNKNOWN.value

                return CascadeDecision(
                    decision=Decision.REVIEW,
                    reason=reason_code,
                    reason_codes=[reason_code, raw.error or "MONITOR_UNKNOWN"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    error=raw.error,
                    raw_output=raw.raw_output,
                )
            if raw.verdict == MonitorVerdict.BENIGN:
                return CascadeDecision(
                    decision=Decision.ALLOW,
                    reason="MONITOR_BENIGN",
                    reason_codes=["MONITOR_BENIGN"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                    raw_output=raw.raw_output,
                )
            if raw.verdict == MonitorVerdict.SUSPICIOUS:
                return CascadeDecision(
                    decision=Decision.DENY,
                    reason="MONITOR_SUSPICIOUS",
                    reason_codes=["MONITOR_SUSPICIOUS"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                    raw_output=raw.raw_output,
                )
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                raw_output=raw.raw_output,
            )

        # B. Response is Decision enum
        if isinstance(raw, Decision):
            if raw == Decision.ALLOW:
                return CascadeDecision(
                    decision=Decision.ALLOW,
                    reason="MONITOR_ALLOW",
                    reason_codes=["MONITOR_ALLOW"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                )
            if raw == Decision.DENY:
                return CascadeDecision(
                    decision=Decision.DENY,
                    reason="MONITOR_DENY",
                    reason_codes=["MONITOR_DENY"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                )
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason="MONITOR_REVIEW",
                reason_codes=["MONITOR_REVIEW"],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
            )

        # C. Response is MonitorVerdict enum
        if isinstance(raw, MonitorVerdict):
            if raw == MonitorVerdict.BENIGN:
                return CascadeDecision(
                    decision=Decision.ALLOW,
                    reason="MONITOR_BENIGN",
                    reason_codes=["MONITOR_BENIGN"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                )
            if raw == MonitorVerdict.SUSPICIOUS:
                return CascadeDecision(
                    decision=Decision.DENY,
                    reason="MONITOR_SUSPICIOUS",
                    reason_codes=["MONITOR_SUSPICIOUS"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                )
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
            )

        # D. Response is string (clean text or raw JSON string)
        if isinstance(raw, str):
            cleaned = raw.strip()

            # Check if this looks like a JSON string payload
            if (
                cleaned.startswith("{")
                or cleaned.startswith("[")
                or ('{"' in cleaned or "{'" in cleaned)
            ):
                try:
                    parsed_json = json.loads(cleaned)
                    return self._parse_dict_response(parsed_json, original_raw=raw)
                except (json.JSONDecodeError, ValueError) as jde:
                    return CascadeDecision(
                        decision=Decision.REVIEW,
                        reason=CascadeFailureReason.MALFORMED_JSON.value,
                        reason_codes=[
                            CascadeFailureReason.MALFORMED_JSON.value,
                            f"JSON_DECODE_ERROR:{jde}",
                        ],
                        policy_verdict=PolicyVerdict.UNDETERMINED,
                        monitor_verdict=MonitorVerdict.UNKNOWN,
                        error=f"Malformed JSON from monitor: {jde}",
                        raw_output=raw,
                    )

            # Plain decision token string
            token = (
                cleaned.upper()
                .replace("*", "")
                .replace("`", "")
                .replace("'", "")
                .replace('"', "")
                .strip()
            )
            if token in {"ALLOW", "PERMIT", "PASS", "BENIGN", "SAFE"}:
                return CascadeDecision(
                    decision=Decision.ALLOW,
                    reason="MONITOR_ALLOW",
                    reason_codes=["MONITOR_ALLOW"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                    raw_output=raw,
                )
            if token in {"DENY", "BLOCK", "FAIL", "SUSPICIOUS", "UNSAFE"}:
                return CascadeDecision(
                    decision=Decision.DENY,
                    reason="MONITOR_DENY",
                    reason_codes=["MONITOR_DENY"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                    raw_output=raw,
                )
            if token in {"REVIEW", "UNSURE"}:
                return CascadeDecision(
                    decision=Decision.REVIEW,
                    reason="MONITOR_REVIEW",
                    reason_codes=["MONITOR_REVIEW"],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    raw_output=raw,
                )
            if token in {"UNKNOWN"}:
                return CascadeDecision(
                    decision=Decision.REVIEW,
                    reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                    reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    raw_output=raw,
                )

            # Unrecognized string output is malformed
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
                reason_codes=[
                    CascadeFailureReason.MALFORMED_OUTPUT.value,
                    f"UNRECOGNIZED_TOKEN:{token[:50]}",
                ],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                error=f"Unrecognized monitor output string: {cleaned[:100]}",
                raw_output=raw,
            )

        # E. Response is dictionary
        if isinstance(raw, dict):
            return self._parse_dict_response(raw, original_raw=str(raw))

        # F. Unsupported type
        return CascadeDecision(
            decision=Decision.REVIEW,
            reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
            reason_codes=[
                CascadeFailureReason.MALFORMED_OUTPUT.value,
                f"UNSUPPORTED_TYPE:{type(raw).__name__}",
            ],
            policy_verdict=PolicyVerdict.UNDETERMINED,
            monitor_verdict=MonitorVerdict.UNKNOWN,
            error=f"Unsupported return type from cascade monitor: {type(raw).__name__}",
            raw_output=str(raw),
        )

    def _parse_dict_response(
        self, data: dict[str, Any], original_raw: Optional[str] = None
    ) -> CascadeDecision:
        val = (
            data.get("decision")
            or data.get("verdict")
            or data.get("prediction")
            or data.get("action")
            or data.get("status")
        )

        if val is None or not isinstance(val, (str, Decision, MonitorVerdict)):
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
                reason_codes=[
                    CascadeFailureReason.MALFORMED_OUTPUT.value,
                    "MISSING_DECISION_FIELD",
                ],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                error="Parsed dictionary lacks a recognizable verdict or decision key",
                raw_output=original_raw,
            )

        if isinstance(val, Decision):
            return self._parse_monitor_response(val)
        if isinstance(val, MonitorVerdict):
            return self._parse_monitor_response(val)

        val_token = val.strip().upper()
        if val_token in {"ALLOW", "PERMIT", "PASS", "BENIGN", "SAFE"}:
            return CascadeDecision(
                decision=Decision.ALLOW,
                reason="MONITOR_ALLOW",
                reason_codes=["MONITOR_ALLOW"],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.BENIGN,
                raw_output=original_raw,
            )
        if val_token in {"DENY", "BLOCK", "FAIL", "SUSPICIOUS", "UNSAFE"}:
            return CascadeDecision(
                decision=Decision.DENY,
                reason="MONITOR_DENY",
                reason_codes=["MONITOR_DENY"],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.SUSPICIOUS,
                raw_output=original_raw,
            )
        if val_token in {"REVIEW", "UNSURE"}:
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason="MONITOR_REVIEW",
                reason_codes=["MONITOR_REVIEW"],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                raw_output=original_raw,
            )
        if val_token in {"UNKNOWN"}:
            return CascadeDecision(
                decision=Decision.REVIEW,
                reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                raw_output=original_raw,
            )

        return CascadeDecision(
            decision=Decision.REVIEW,
            reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
            reason_codes=[
                CascadeFailureReason.MALFORMED_OUTPUT.value,
                f"UNRECOGNIZED_DICT_VALUE:{val_token}",
            ],
            policy_verdict=PolicyVerdict.UNDETERMINED,
            monitor_verdict=MonitorVerdict.UNKNOWN,
            error=f"Unrecognized decision value in dict: {val_token}",
            raw_output=original_raw,
        )

    def _build_default_view(
        self,
        action: Optional[Any],
        tool: Optional[str],
        arguments: Optional[dict[str, Any]],
    ) -> MonitorView:
        if isinstance(action, MonitorView):
            return action

        if isinstance(action, CanonicalAction):
            c_action = action
        elif isinstance(action, ActionRequest):
            action_hash = compute_action_hash(action.session_id, 1, action.tool, action.arguments)
            c_action = CanonicalAction(
                action_id="act_cascade_adapter",
                session_id=action.session_id,
                seq=1,
                tool=action.tool,
                arguments=action.arguments,
                action_hash=action_hash,
            )
        elif tool is not None:
            args = arguments or {}
            action_hash = compute_action_hash("session_cascade", 1, tool, args)
            c_action = CanonicalAction(
                action_id="act_cascade_adapter",
                session_id="session_cascade",
                seq=1,
                tool=tool,
                arguments=args,
                action_hash=action_hash,
            )
        elif isinstance(action, dict):
            t = action.get("tool", "unknown_tool")
            args = action.get("arguments", {})
            action_hash = compute_action_hash("session_cascade", 1, t, args)
            c_action = CanonicalAction(
                action_id="act_cascade_adapter",
                session_id="session_cascade",
                seq=1,
                tool=t,
                arguments=args,
                action_hash=action_hash,
            )
        else:
            action_hash = compute_action_hash("session_cascade", 1, "unknown_tool", {})
            c_action = CanonicalAction(
                action_id="act_cascade_adapter",
                session_id="session_cascade",
                seq=1,
                tool="unknown_tool",
                arguments={},
                action_hash=action_hash,
            )

        return MonitorView(
            monitor_id=self.monitor_id,
            action=c_action,
            registry_facts={},
            state_summary={},
        )

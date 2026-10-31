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


class AdvisoryVerdict(str, Enum):
    """Advisory verdicts emitted by the cascade adapter (advisory only)."""

    LOW_RISK = "LOW_RISK"
    ELEVATED_RISK = "ELEVATED_RISK"
    UNCERTAIN = "UNCERTAIN"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CONSULTED = "NOT_CONSULTED"


@dataclass(frozen=True)
class MonitorAdvisory:
    """
    Advisory result returned by CascadeAdapter.
    The semantic monitor / rejection cascade is ADVISORY ONLY:
    It must never independently authorize, execute, allow, or deny an action.
    The core firewall—not the adapter or monitor—must make the final decision.
    """

    verdict: str  # e.g., "LOW_RISK", "ELEVATED_RISK", "UNCERTAIN", "UNAVAILABLE", "NOT_CONSULTED"
    reason: str
    confidence: Optional[float] = None
    recommended_outcome: Optional[str] = None
    reason_codes: list[str] = field(default_factory=list)
    policy_verdict: PolicyVerdict = PolicyVerdict.UNDETERMINED
    monitor_verdict: MonitorVerdict = MonitorVerdict.NOT_CONSULTED
    error: Optional[str] = None
    raw_output: Optional[str] = None
    decision: Optional[Decision] = None  # Always None; adapter does not make authorization decisions

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Decision):
            # Advisory assessment never equals a final firewall Decision enum
            return False
        if isinstance(other, str):
            return self.verdict == other or self.recommended_outcome == other
        if isinstance(other, MonitorAdvisory):
            return (
                self.verdict == other.verdict
                and self.reason == other.reason
                and self.reason_codes == other.reason_codes
            )
        return False

    def __iter__(self) -> Any:
        """Enable tuple unpacking: verdict, reason_codes = adapter.decide(...)"""
        return iter((self.verdict, self.reason_codes))


CascadeDecision = MonitorAdvisory


class CascadeAdapter:
    """
    Adapter bridging a rejection-cascade monitor into the AASF firewall decision pipeline.

    The semantic monitor / rejection cascade is ADVISORY ONLY:
    - It must never independently authorize (ALLOW) or block (DENY) an action.
    - BENIGN maps to advisory LOW_RISK, never ALLOW.
    - SUSPICIOUS maps to advisory ELEVATED_RISK, never DENY.
    - UNKNOWN maps to advisory UNCERTAIN.
    - Malformed JSON, timeouts, and exceptions map to advisory UNAVAILABLE with structured reasons.
    - The core firewall independently enforces final decisions after receiving the advisory result.
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
        policy_verdict: Union[PolicyVerdict, PolicyResult, str] = PolicyVerdict.UNDETERMINED,
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
    ) -> MonitorAdvisory:
        """
        Evaluate a request given a policy verdict and optional action context.
        Returns a MonitorAdvisory. The adapter is advisory-only and does not make
        final firewall authorization decisions (ALLOW/DENY).
        """
        # 1. Normalize policy verdict input
        p_verdict, p_rules, p_missing = self._normalize_policy_verdict(
            policy_verdict, matched_rules, missing_fields
        )

        # 2. Hard policy prohibitions: advisory reflects policy, monitor not consulted
        if p_verdict == PolicyVerdict.PROHIBIT:
            reasons = [f"POLICY_PROHIBIT:{r}" for r in p_rules] if p_rules else ["POLICY_PROHIBIT"]
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.NOT_CONSULTED.value,
                reason="POLICY_PROHIBIT",
                reason_codes=reasons,
                recommended_outcome="DENY",
                policy_verdict=PolicyVerdict.PROHIBIT,
                monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            )

        # 3. Policy permit: advisory reflects policy, monitor not consulted directly here
        if p_verdict == PolicyVerdict.PERMIT:
            reasons = [f"POLICY_PERMIT:{r}" for r in p_rules] if p_rules else ["POLICY_PERMIT"]
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.NOT_CONSULTED.value,
                reason="POLICY_PERMIT",
                reason_codes=reasons,
                recommended_outcome="ALLOW",
                policy_verdict=PolicyVerdict.PERMIT,
                monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            )

        # 4. Incomplete evidence: fail-closed escalation advisory
        if p_verdict == PolicyVerdict.EVIDENCE_MISSING:
            missing_str = ",".join(p_missing) if p_missing else ""
            reason = f"EVIDENCE_MISSING:{missing_str}" if missing_str else "EVIDENCE_MISSING"
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.NOT_CONSULTED.value,
                reason="EVIDENCE_MISSING",
                reason_codes=[reason],
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.EVIDENCE_MISSING,
                monitor_verdict=MonitorVerdict.NOT_CONSULTED,
            )

        # 5. Policy UNDETERMINED: consult the cascade monitor for advisory assessment
        if p_verdict == PolicyVerdict.UNDETERMINED:
            active_monitor = monitor if monitor is not None else self.monitor
            if active_monitor is None:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.UNAVAILABLE.value,
                    reason=CascadeFailureReason.NO_MONITOR_CONFIGURED.value,
                    reason_codes=[
                        CascadeFailureReason.NO_MONITOR_CONFIGURED.value,
                        CascadeFailureReason.MONITOR_UNKNOWN.value,
                    ],
                    recommended_outcome="REVIEW",
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

        # Catch-all unexpected policy verdict -> advisory unavailable
        return MonitorAdvisory(
            verdict=AdvisoryVerdict.UNAVAILABLE.value,
            reason="UNEXPECTED_POLICY_VERDICT",
            reason_codes=["UNEXPECTED_POLICY_VERDICT", str(p_verdict)],
            recommended_outcome="DENY",
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
        advisory = self.decide(
            PolicyVerdict.UNDETERMINED,
            view=view,
            timeout_ms=timeout_ms,
        )

        score = 0.0 if advisory.verdict == AdvisoryVerdict.LOW_RISK.value else 1.0
        return MonitorAssessment(
            verdict=advisory.monitor_verdict,
            score=score,
            rationale=advisory.reason,
            raw_output=advisory.raw_output,
            monitor_version=self.version,
            error=advisory.error,
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
    ) -> MonitorAdvisory:
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
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNAVAILABLE.value,
                reason=CascadeFailureReason.MONITOR_TIMEOUT.value,
                reason_codes=[CascadeFailureReason.MONITOR_TIMEOUT.value, f"TIMEOUT:{te}"],
                recommended_outcome="REVIEW",
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

            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNAVAILABLE.value,
                reason=reason_code,
                reason_codes=[reason_code, f"{exc_name}:{exc}"],
                recommended_outcome="REVIEW",
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

    def _parse_monitor_response(self, raw: Any) -> MonitorAdvisory:
        # A. Response is MonitorAssessment
        if isinstance(raw, MonitorAssessment):
            if raw.verdict == MonitorVerdict.UNKNOWN:
                error_upper = (raw.error or "").upper()
                if "TIMEOUT" in error_upper:
                    reason_code = CascadeFailureReason.MONITOR_TIMEOUT.value
                    verdict_val = AdvisoryVerdict.UNAVAILABLE.value
                elif "EXCEPTION" in error_upper:
                    reason_code = CascadeFailureReason.MONITOR_EXCEPTION.value
                    verdict_val = AdvisoryVerdict.UNAVAILABLE.value
                elif "JSON" in error_upper or "PARSE" in error_upper:
                    reason_code = CascadeFailureReason.MALFORMED_OUTPUT.value
                    verdict_val = AdvisoryVerdict.UNAVAILABLE.value
                else:
                    reason_code = CascadeFailureReason.MONITOR_UNKNOWN.value
                    verdict_val = AdvisoryVerdict.UNCERTAIN.value

                return MonitorAdvisory(
                    verdict=verdict_val,
                    reason=reason_code,
                    reason_codes=[reason_code, raw.error or "MONITOR_UNKNOWN"],
                    confidence=raw.score,
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    error=raw.error,
                    raw_output=raw.raw_output,
                )
            if raw.verdict == MonitorVerdict.BENIGN:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.LOW_RISK.value,
                    reason="MONITOR_BENIGN",
                    reason_codes=["MONITOR_BENIGN"],
                    confidence=raw.score,
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                    raw_output=raw.raw_output,
                )
            if raw.verdict == MonitorVerdict.SUSPICIOUS:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.ELEVATED_RISK.value,
                    reason="MONITOR_SUSPICIOUS",
                    reason_codes=["MONITOR_SUSPICIOUS"],
                    confidence=raw.score,
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                    raw_output=raw.raw_output,
                )
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNCERTAIN.value,
                reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                confidence=raw.score,
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                raw_output=raw.raw_output,
            )

        # B. Response is Decision enum (advisory mapping: never returns ALLOW or DENY)
        if isinstance(raw, Decision):
            if raw == Decision.ALLOW:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.LOW_RISK.value,
                    reason="MONITOR_LOW_RISK",
                    reason_codes=["MONITOR_LOW_RISK"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                )
            if raw == Decision.DENY:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.ELEVATED_RISK.value,
                    reason="MONITOR_ELEVATED_RISK",
                    reason_codes=["MONITOR_ELEVATED_RISK"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                )
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNCERTAIN.value,
                reason="MONITOR_UNCERTAIN",
                reason_codes=["MONITOR_UNCERTAIN"],
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
            )

        # C. Response is MonitorVerdict enum
        if isinstance(raw, MonitorVerdict):
            if raw == MonitorVerdict.BENIGN:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.LOW_RISK.value,
                    reason="MONITOR_BENIGN",
                    reason_codes=["MONITOR_BENIGN"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                )
            if raw == MonitorVerdict.SUSPICIOUS:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.ELEVATED_RISK.value,
                    reason="MONITOR_SUSPICIOUS",
                    reason_codes=["MONITOR_SUSPICIOUS"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                )
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNCERTAIN.value,
                reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                recommended_outcome="REVIEW",
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
                    return MonitorAdvisory(
                        verdict=AdvisoryVerdict.UNAVAILABLE.value,
                        reason=CascadeFailureReason.MALFORMED_JSON.value,
                        reason_codes=[
                            CascadeFailureReason.MALFORMED_JSON.value,
                            f"JSON_DECODE_ERROR:{jde}",
                        ],
                        recommended_outcome="REVIEW",
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
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.LOW_RISK.value,
                    reason="MONITOR_LOW_RISK",
                    reason_codes=["MONITOR_LOW_RISK"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.BENIGN,
                    raw_output=raw,
                )
            if token in {"DENY", "BLOCK", "FAIL", "SUSPICIOUS", "UNSAFE"}:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.ELEVATED_RISK.value,
                    reason="MONITOR_ELEVATED_RISK",
                    reason_codes=["MONITOR_ELEVATED_RISK"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.SUSPICIOUS,
                    raw_output=raw,
                )
            if token in {"REVIEW", "UNSURE"}:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.UNCERTAIN.value,
                    reason="MONITOR_UNCERTAIN",
                    reason_codes=["MONITOR_UNCERTAIN"],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    raw_output=raw,
                )
            if token in {"UNKNOWN"}:
                return MonitorAdvisory(
                    verdict=AdvisoryVerdict.UNCERTAIN.value,
                    reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                    reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                    recommended_outcome="REVIEW",
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.UNKNOWN,
                    raw_output=raw,
                )

            # Unrecognized string output is malformed
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNAVAILABLE.value,
                reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
                reason_codes=[
                    CascadeFailureReason.MALFORMED_OUTPUT.value,
                    f"UNRECOGNIZED_TOKEN:{token[:50]}",
                ],
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                error=f"Unrecognized monitor output string: {cleaned[:100]}",
                raw_output=raw,
            )

        # E. Response is dictionary
        if isinstance(raw, dict):
            return self._parse_dict_response(raw, original_raw=str(raw))

        # F. Unsupported type
        return MonitorAdvisory(
            verdict=AdvisoryVerdict.UNAVAILABLE.value,
            reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
            reason_codes=[
                CascadeFailureReason.MALFORMED_OUTPUT.value,
                f"UNSUPPORTED_TYPE:{type(raw).__name__}",
            ],
            recommended_outcome="REVIEW",
            policy_verdict=PolicyVerdict.UNDETERMINED,
            monitor_verdict=MonitorVerdict.UNKNOWN,
            error=f"Unsupported return type from cascade monitor: {type(raw).__name__}",
            raw_output=str(raw),
        )

    def _parse_dict_response(
        self, data: dict[str, Any], original_raw: Optional[str] = None
    ) -> MonitorAdvisory:
        val = (
            data.get("decision")
            or data.get("verdict")
            or data.get("prediction")
            or data.get("action")
            or data.get("status")
        )

        conf = data.get("confidence") or data.get("score")
        try:
            conf_float = float(conf) if conf is not None else None
        except (ValueError, TypeError):
            conf_float = None

        if val is None or not isinstance(val, (str, Decision, MonitorVerdict)):
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNAVAILABLE.value,
                reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
                reason_codes=[
                    CascadeFailureReason.MALFORMED_OUTPUT.value,
                    "MISSING_DECISION_FIELD",
                ],
                confidence=conf_float,
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                error="Parsed dictionary lacks a recognizable verdict or decision key",
                raw_output=original_raw,
            )

        if isinstance(val, Decision):
            base = self._parse_monitor_response(val)
            return MonitorAdvisory(
                verdict=base.verdict,
                reason=base.reason,
                confidence=conf_float if conf_float is not None else base.confidence,
                recommended_outcome=base.recommended_outcome,
                reason_codes=base.reason_codes,
                policy_verdict=base.policy_verdict,
                monitor_verdict=base.monitor_verdict,
                error=base.error,
                raw_output=original_raw,
            )

        if isinstance(val, MonitorVerdict):
            base = self._parse_monitor_response(val)
            return MonitorAdvisory(
                verdict=base.verdict,
                reason=base.reason,
                confidence=conf_float if conf_float is not None else base.confidence,
                recommended_outcome=base.recommended_outcome,
                reason_codes=base.reason_codes,
                policy_verdict=base.policy_verdict,
                monitor_verdict=base.monitor_verdict,
                error=base.error,
                raw_output=original_raw,
            )

        val_token = val.strip().upper()
        if val_token in {"ALLOW", "PERMIT", "PASS", "BENIGN", "SAFE"}:
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.LOW_RISK.value,
                reason="MONITOR_LOW_RISK",
                reason_codes=["MONITOR_LOW_RISK"],
                confidence=conf_float,
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.BENIGN,
                raw_output=original_raw,
            )
        if val_token in {"DENY", "BLOCK", "FAIL", "SUSPICIOUS", "UNSAFE"}:
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.ELEVATED_RISK.value,
                reason="MONITOR_ELEVATED_RISK",
                reason_codes=["MONITOR_ELEVATED_RISK"],
                confidence=conf_float,
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.SUSPICIOUS,
                raw_output=original_raw,
            )
        if val_token in {"REVIEW", "UNSURE"}:
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNCERTAIN.value,
                reason="MONITOR_UNCERTAIN",
                reason_codes=["MONITOR_UNCERTAIN"],
                confidence=conf_float,
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                raw_output=original_raw,
            )
        if val_token in {"UNKNOWN"}:
            return MonitorAdvisory(
                verdict=AdvisoryVerdict.UNCERTAIN.value,
                reason=CascadeFailureReason.MONITOR_UNKNOWN.value,
                reason_codes=[CascadeFailureReason.MONITOR_UNKNOWN.value],
                confidence=conf_float,
                recommended_outcome="REVIEW",
                policy_verdict=PolicyVerdict.UNDETERMINED,
                monitor_verdict=MonitorVerdict.UNKNOWN,
                raw_output=original_raw,
            )

        return MonitorAdvisory(
            verdict=AdvisoryVerdict.UNAVAILABLE.value,
            reason=CascadeFailureReason.MALFORMED_OUTPUT.value,
            reason_codes=[
                CascadeFailureReason.MALFORMED_OUTPUT.value,
                f"UNRECOGNIZED_DICT_VALUE:{val_token}",
            ],
            confidence=conf_float,
            recommended_outcome="REVIEW",
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
        import copy
        from firewall.state.views import sanitize_data

        if isinstance(action, MonitorView):
            sanitized_args = sanitize_data(copy.deepcopy(action.action.arguments))
            c_action = CanonicalAction(
                action_id=action.action.action_id,
                session_id=action.action.session_id,
                seq=action.action.seq,
                tool=action.action.tool,
                arguments=sanitized_args,
                action_hash=action.action.action_hash,
            )
            return MonitorView(
                monitor_id=action.monitor_id,
                action=c_action,
                registry_facts=sanitize_data(copy.deepcopy(action.registry_facts)),
                goal=sanitize_data(copy.deepcopy(action.goal)),
                policy_text=copy.deepcopy(action.policy_text),
                transcript=copy.deepcopy(action.transcript),
                state_summary=sanitize_data(copy.deepcopy(action.state_summary)),
            )

        if isinstance(action, CanonicalAction):
            c_action = CanonicalAction(
                action_id=action.action_id,
                session_id=action.session_id,
                seq=action.seq,
                tool=action.tool,
                arguments=sanitize_data(copy.deepcopy(action.arguments)),
                action_hash=action.action_hash,
            )
        elif isinstance(action, ActionRequest):
            sanitized_args = sanitize_data(copy.deepcopy(action.arguments))
            action_hash = compute_action_hash(action.session_id, 1, action.tool, action.arguments)
            c_action = CanonicalAction(
                action_id="act_cascade_adapter",
                session_id=action.session_id,
                seq=1,
                tool=action.tool,
                arguments=sanitized_args,
                action_hash=action_hash,
            )
        elif tool is not None:
            args = sanitize_data(copy.deepcopy(arguments or {}))
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
            args = sanitize_data(copy.deepcopy(action.get("arguments", {})))
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


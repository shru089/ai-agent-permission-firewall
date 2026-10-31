"""
Unit and integration tests for CascadeAdapter.
Verifies all required routing behaviors, fail-closed monitor escalation,
and structured failure reporting without real network or LLM calls.

Test coverage:
- PROHIBIT -> DENY
- Valid PERMIT -> ALLOW
- EVIDENCE_MISSING -> REVIEW
- UNDETERMINED with valid monitor decision -> ALLOW / DENY / REVIEW
- UNKNOWN -> REVIEW
- Timeout -> REVIEW
- Exception -> REVIEW
- Malformed JSON -> REVIEW
- Never return ALLOW after monitor failure
- Record structured failure reason for REVIEW escalation
"""

from unittest.mock import MagicMock
from typing import Any

import pytest

from firewall.cascade.adapter import (
    CascadeAdapter,
    CascadeFailureReason,
)
from firewall.contracts.enums import (
    Decision,
    MonitorVerdict,
    PolicyVerdict,
)
from firewall.contracts.models import (
    CanonicalAction,
    MonitorAssessment,
    MonitorView,
    PolicyResult,
)
from firewall.monitor.mock import DeterministicMockMonitor

# ==============================================================================
# 1. Deterministic Policy Verdict Tests (PROHIBIT, PERMIT, EVIDENCE_MISSING)
# ==============================================================================


@pytest.mark.unit
def test_prohibit_returns_deny_without_calling_monitor() -> None:
    """
    PROHIBIT advisory outcome is DENY.
    Hard policy prohibitions dominate unconditionally (INV-03).
    The cascade monitor must not be called.
    """
    mock_monitor = MagicMock()
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.PROHIBIT)

    assert result.recommended_outcome == "DENY"
    assert result != Decision.DENY
    assert "POLICY_PROHIBIT" in result.reason
    assert result.policy_verdict == PolicyVerdict.PROHIBIT
    assert result.monitor_verdict == MonitorVerdict.NOT_CONSULTED

    # Invariant: monitor is NEVER called on PROHIBIT
    mock_monitor.assess.assert_not_called()
    mock_monitor.assert_not_called()


@pytest.mark.unit
def test_prohibit_with_matched_rules() -> None:
    """PROHIBIT records matched rules in reason_codes."""
    adapter = CascadeAdapter()
    result = adapter.decide(
        PolicyVerdict.PROHIBIT,
        matched_rules=["RULE_NO_EXFILTRATION", "RULE_NO_DROP_TABLE"],
    )

    assert result.recommended_outcome == "DENY"
    assert "POLICY_PROHIBIT:RULE_NO_EXFILTRATION" in result.reason_codes
    assert "POLICY_PROHIBIT:RULE_NO_DROP_TABLE" in result.reason_codes


@pytest.mark.unit
def test_permit_returns_allow_without_calling_monitor() -> None:
    """
    Valid PERMIT advisory outcome is ALLOW.
    Unambiguous policy permits do not consult the monitor.
    """
    mock_monitor = MagicMock()
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.PERMIT)

    assert result.recommended_outcome == "ALLOW"
    assert result != Decision.ALLOW
    assert "POLICY_PERMIT" in result.reason
    assert result.policy_verdict == PolicyVerdict.PERMIT
    assert result.monitor_verdict == MonitorVerdict.NOT_CONSULTED

    # Invariant: monitor is not called on PERMIT
    mock_monitor.assess.assert_not_called()


@pytest.mark.unit
def test_permit_from_policy_result_object() -> None:
    """Accepts a PolicyResult object directly."""
    policy_res = PolicyResult(
        verdict=PolicyVerdict.PERMIT,
        matched_rules=["RULE_BENIGN_READ"],
        policy_hash="hash123",
        registry_hash="reghash456",
    )
    adapter = CascadeAdapter()
    result = adapter.decide(policy_res)

    assert result.recommended_outcome == "ALLOW"
    assert "POLICY_PERMIT:RULE_BENIGN_READ" in result.reason_codes


@pytest.mark.unit
def test_evidence_missing_returns_review_without_calling_monitor() -> None:
    """
    EVIDENCE_MISSING -> REVIEW.
    Incomplete authorization state triggers fail-closed human review (INV-04).
    """
    mock_monitor = MagicMock()
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(
        PolicyVerdict.EVIDENCE_MISSING,
        missing_fields=["resource.classification", "destination.zone"],
    )

    assert result.recommended_outcome == "REVIEW"
    assert "EVIDENCE_MISSING" in result.reason
    assert "EVIDENCE_MISSING:resource.classification,destination.zone" in result.reason_codes
    assert result.policy_verdict == PolicyVerdict.EVIDENCE_MISSING
    assert result.monitor_verdict == MonitorVerdict.NOT_CONSULTED

    mock_monitor.assess.assert_not_called()


# ==============================================================================
# 2. UNDETERMINED Policy Verdict: Advisory Monitor Verdicts
# ==============================================================================


@pytest.mark.unit
def test_undetermined_calls_monitor_allow() -> None:
    """UNDETERMINED policy + monitor BENIGN maps to advisory LOW_RISK, NOT ALLOW."""
    mock_monitor = DeterministicMockMonitor(verdict=MonitorVerdict.BENIGN)
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "LOW_RISK"
    assert result != Decision.ALLOW
    assert result.decision is None
    assert result.monitor_verdict == MonitorVerdict.BENIGN


@pytest.mark.unit
def test_undetermined_calls_monitor_deny() -> None:
    """UNDETERMINED policy + monitor SUSPICIOUS maps to advisory ELEVATED_RISK, NOT DENY."""
    mock_monitor = DeterministicMockMonitor(verdict=MonitorVerdict.SUSPICIOUS)
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "ELEVATED_RISK"
    assert result != Decision.DENY
    assert result.decision is None
    assert result.monitor_verdict == MonitorVerdict.SUSPICIOUS


@pytest.mark.unit
def test_undetermined_with_string_decision_allow() -> None:
    """Monitor returning valid string 'PASS' / 'ALLOW' maps to advisory LOW_RISK, not Decision.ALLOW."""
    fake_monitor = MagicMock(return_value="PASS")
    adapter = CascadeAdapter(monitor=fake_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)
    assert result.verdict == "LOW_RISK"
    assert result != Decision.ALLOW


@pytest.mark.unit
def test_undetermined_with_string_decision_fail() -> None:
    """Monitor returning valid string 'FAIL' / 'DENY' maps to advisory ELEVATED_RISK, not Decision.DENY."""
    fake_monitor = MagicMock(return_value="FAIL")
    adapter = CascadeAdapter(monitor=fake_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)
    assert result.verdict == "ELEVATED_RISK"
    assert result != Decision.DENY


@pytest.mark.unit
def test_undetermined_with_valid_json_dict() -> None:
    """Monitor returning valid JSON dict maps accurately to LOW_RISK."""
    fake_monitor = MagicMock(return_value={"verdict": "BENIGN", "confidence": 0.99})
    adapter = CascadeAdapter(monitor=fake_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)
    assert result.verdict == "LOW_RISK"
    assert result != Decision.ALLOW
    assert result.monitor_verdict == MonitorVerdict.BENIGN
    assert result.confidence == 0.99


# ==============================================================================
# 3. Fail-Closed Behavior: UNKNOWN, Timeout, Exception, Malformed Output
# ==============================================================================


@pytest.mark.unit
def test_unknown_returns_review() -> None:
    """
    UNKNOWN -> UNCERTAIN advisory.
    Uncertain monitor assessment must fail-closed to REVIEW (INV-04).
    Must record MONITOR_UNKNOWN structured failure reason.
    """
    mock_monitor = DeterministicMockMonitor(verdict=MonitorVerdict.UNKNOWN)
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNCERTAIN"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MONITOR_UNKNOWN.value in result.reason
    assert result.monitor_verdict == MonitorVerdict.UNKNOWN


@pytest.mark.unit
def test_unknown_string_or_dict_returns_review() -> None:
    """Monitor returning string 'UNKNOWN' or dict {'decision': 'UNKNOWN'} maps to UNCERTAIN."""
    adapter = CascadeAdapter(monitor=lambda: "UNKNOWN")
    result = adapter.decide(PolicyVerdict.UNDETERMINED)
    assert result.verdict == "UNCERTAIN"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MONITOR_UNKNOWN.value in result.reason_codes

    adapter2 = CascadeAdapter(monitor=lambda: {"decision": "UNKNOWN"})
    result2 = adapter2.decide(PolicyVerdict.UNDETERMINED)
    assert result2.verdict == "UNCERTAIN"
    assert result2.decision != Decision.ALLOW


@pytest.mark.unit
def test_timeout_returns_review() -> None:
    """
    Timeout -> UNAVAILABLE advisory.
    Monitor timeout must fail-closed to REVIEW (INV-04, D-37).
    Must record MONITOR_TIMEOUT structured failure reason.
    """
    mock_monitor = DeterministicMockMonitor(simulate_timeout=True)
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MONITOR_TIMEOUT.value in result.reason
    assert any("TIMEOUT" in r for r in result.reason_codes)
    assert result.error is not None


@pytest.mark.unit
def test_timeout_exception_direct_returns_review() -> None:
    """TimeoutError raised by monitor callable returns UNAVAILABLE."""

    def timing_out_monitor(*args: Any, **kwargs: Any) -> Any:
        raise TimeoutError("Ollama HTTP connection timed out after 1500ms")

    adapter = CascadeAdapter(monitor=timing_out_monitor)
    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MONITOR_TIMEOUT.value in result.reason


@pytest.mark.unit
def test_exception_returns_review() -> None:
    """
    Exception -> UNAVAILABLE advisory.
    Unhandled monitor exceptions must fail-closed to REVIEW (INV-04, D-37).
    Must record MONITOR_EXCEPTION structured failure reason.
    """
    mock_monitor = DeterministicMockMonitor(
        raise_exception=RuntimeError("Connection refused to inference worker")
    )
    adapter = CascadeAdapter(monitor=mock_monitor)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MONITOR_EXCEPTION.value in result.reason
    assert any("RuntimeError" in r for r in result.reason_codes)
    assert "Connection refused" in str(result.error)


@pytest.mark.unit
def test_arbitrary_callable_exception_returns_review() -> None:
    """Monitor callable raising ValueError or NetworkError maps to UNAVAILABLE."""

    def broken_monitor() -> None:
        raise ValueError("Corrupt weights tensor")

    adapter = CascadeAdapter(monitor=broken_monitor)
    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MONITOR_EXCEPTION.value in result.reason


@pytest.mark.unit
def test_malformed_json_returns_review() -> None:
    """
    Malformed JSON -> UNAVAILABLE advisory.
    Unparseable JSON emitted by model fails-closed to REVIEW.
    Must record MALFORMED_JSON structured failure reason.
    """
    # Truncated or syntax-broken JSON from LLM
    broken_json_output = '{"verdict": "PASS", "confidence": '
    adapter = CascadeAdapter(monitor=lambda: broken_json_output)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MALFORMED_JSON.value in result.reason
    assert any("JSON_DECODE_ERROR" in r for r in result.reason_codes)
    assert result.raw_output == broken_json_output


@pytest.mark.unit
def test_malformed_output_missing_fields_returns_review() -> None:
    """Dictionary output lacking valid decision/verdict fields fails-closed to UNAVAILABLE."""
    adapter = CascadeAdapter(monitor=lambda: {"unrelated_field": 42})

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MALFORMED_OUTPUT.value in result.reason
    assert "MISSING_DECISION_FIELD" in result.reason_codes


@pytest.mark.unit
def test_malformed_output_unrecognized_string_returns_review() -> None:
    """Unrecognized, non-JSON free text output fails-closed to UNAVAILABLE."""
    adapter = CascadeAdapter(monitor=lambda: "I am an AI and I think this might be okay")

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.MALFORMED_OUTPUT.value in result.reason


# ==============================================================================
# 4. Invariant: Never Return ALLOW After Monitor Failure
# ==============================================================================


@pytest.mark.parametrize(
    "fault_output",
    [
        TimeoutError("timed out"),
        RuntimeError("inference model crashed"),
        ValueError("invalid prompt buffer"),
        MonitorVerdict.UNKNOWN,
        "UNKNOWN",
        '{"verdict": "UNKNOWN"}',
        '{"status": "broken_state"}',
        '{"broken: json',
        "GARBAGE_OUTPUT_TEXT",
        None,
        42,
        [],
    ],
)
@pytest.mark.unit
def test_never_return_allow_after_monitor_failure(fault_output: Any) -> None:
    """
    Critical Invariant: Under NO failure condition (exception, timeout, malformed JSON,
    empty or corrupt output, or UNKNOWN verdict) can the adapter EVER return ALLOW.
    """
    if isinstance(fault_output, Exception):
        mock_monitor = MagicMock(side_effect=fault_output)
    else:
        mock_monitor = MagicMock(return_value=fault_output)

    adapter = CascadeAdapter(monitor=mock_monitor)
    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    # Hard Invariant check
    assert result.decision != Decision.ALLOW, (
        f"Critical safety invariant violated: adapter returned ALLOW for fault {fault_output!r}"
    )
    assert result.verdict in ("UNCERTAIN", "UNAVAILABLE")
    assert result.reason != ""
    assert len(result.reason_codes) > 0


# ==============================================================================
# 5. Missing Monitor Configuration Fail-Closed
# ==============================================================================


@pytest.mark.unit
def test_no_monitor_configured_fails_closed_to_review() -> None:
    """When policy is UNDETERMINED and no monitor is configured, return UNAVAILABLE."""
    adapter = CascadeAdapter(monitor=None)

    result = adapter.decide(PolicyVerdict.UNDETERMINED)

    assert result.verdict == "UNAVAILABLE"
    assert result.decision != Decision.ALLOW
    assert CascadeFailureReason.NO_MONITOR_CONFIGURED.value in result.reason_codes


# ==============================================================================
# 6. Usability and Contract Compatibility Tests
# ==============================================================================


@pytest.mark.unit
def test_tuple_unpacking_and_equality() -> None:
    """Verify MonitorAdvisory / CascadeDecision supports object access, unpacking, and equality."""
    adapter = CascadeAdapter()
    result = adapter.decide(PolicyVerdict.PROHIBIT)

    # Object access
    assert result.recommended_outcome == "DENY"
    # Never equals final Decision enum
    assert result != Decision.DENY
    # Direct equality with string
    assert result == "DENY"

    # Tuple unpacking
    verdict, reasons = adapter.decide(PolicyVerdict.PROHIBIT)
    assert isinstance(reasons, list)
    assert "POLICY_PROHIBIT" in reasons[0]



@pytest.mark.unit
def test_assess_protocol_compatibility() -> None:
    """Verify CascadeAdapter satisfies the Monitor protocol."""
    adapter = CascadeAdapter(monitor=lambda: "PASS")

    action = CanonicalAction(
        action_id="act_test_01",
        session_id="sess_01",
        seq=1,
        tool="test_tool",
        arguments={},
        action_hash="hash123",
    )
    view = MonitorView(
        monitor_id="cascade_adapter",
        action=action,
        registry_facts={},
    )

    assessment = adapter.assess(view)
    assert isinstance(assessment, MonitorAssessment)
    assert assessment.verdict == MonitorVerdict.BENIGN
    assert assessment.score == 0.0

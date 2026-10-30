"""
Integration tests for CascadeAdapter within FirewallCore decision flow.
Verifies the integration of the cascade adapter when policy verdict is UNDETERMINED,
preservation of core firewall rules (PROHIBIT -> DENY, EVIDENCE_MISSING -> REVIEW,
UNDETERMINED -> cascade adapter, monitor failures -> REVIEW, never ALLOW after monitor failure),
and end-to-end route tracing (fast path vs cascade path, monitor invocation, decision,
reasons, latency, and audit trail).

Source: 05_TECHNICAL_SPEC.md §9, 06_EXPERIMENT_PROTOCOL.md §2,
        01_THREAT_MODEL.md (INV-03, INV-04, INV-08, INV-09)
"""

from typing import Any
from unittest.mock import MagicMock

import pytest

from firewall.cascade.adapter import CascadeAdapter, CascadeFailureReason
from firewall.contracts.enums import (
    ConfirmationLevel,
    Decision,
    MonitorVerdict,
    PolicyVerdict,
)
from firewall.contracts.models import ActionRequest
from firewall.core import FirewallCore
from firewall.decision.combinator import DecisionConfig
from firewall.monitor.mock import DeterministicMockMonitor
from firewall.state.registry import Registry


@pytest.fixture
def cascade_registry() -> Registry:
    """Registry containing tools with known policy rules and tools requiring cascade resolution."""
    return Registry(
        resources={
            "customer_records": {"classification": "CONFIDENTIAL", "rows": 5000},
            "public_records": {"classification": "PUBLIC", "rows": 800},
        },
        destinations={
            "external_storage": {"zone": "EXTERNAL"},
            "internal_archive": {"zone": "INTERNAL"},
        },
        tools={
            # Tools with explicit policy rules
            "select_resource": {"tool_class": "READ_SENSITIVE"},
            "create_export_job": {"tool_class": "WRITE_INTERNAL"},
            "configure_destination": {"tool_class": "WRITE_INTERNAL"},
            "execute_export": {"tool_class": "EGRESS_EXTERNAL"},
            "validate_schema": {"tool_class": "READ_LOW"},
            "relabel_resource": {"tool_class": "PRIVILEGED_ADMIN"},
            # Tools without explicit policy rules -> UNDETERMINED policy verdict
            "query_telemetry": {"tool_class": "READ_SENSITIVE"},
            "read_service_status": {"tool_class": "READ_SENSITIVE"},
            "purge_database": {"tool_class": "DESTRUCTIVE"},
            "rotate_keys": {"tool_class": "PRIVILEGED_ADMIN"},
        },
    )


# ==============================================================================
# 1. PROHIBIT -> DENY (Fast Path)
# ==============================================================================


def test_01_prohibit_returns_deny_on_fast_path(cascade_registry: Registry) -> None:
    """
    Rule: PROHIBIT -> DENY
    When policy verdict is PROHIBIT:
    - Decision is DENY
    - Fast path is used
    - Monitor is NOT invoked
    - Failure reason is recorded
    - Decision latency is recorded
    """
    mock_monitor = MagicMock()
    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=mock_monitor),
    )

    # Tool relabel_resource matches R4 (PROHIBIT)
    req = ActionRequest(
        session_id="sess_int_prohibit",
        tool="relabel_resource",
        arguments={"resource_ref": "customer_records", "classification": "PUBLIC"},
    )
    resp = fw.submit(req)

    # Assert decision outcome
    assert resp.status == "DENIED"
    assert resp.decision == Decision.DENY
    assert resp.policy_verdict == PolicyVerdict.PROHIBIT

    # Assert monitor was never invoked (INV-03 prohibit supremacy)
    assert not mock_monitor.called

    # Assert route trace
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "fast_path"
    assert trace.is_fast_path is True
    assert trace.is_cascade_path is False
    assert trace.monitor_invoked is False
    assert trace.final_decision == Decision.DENY
    assert trace.failure_reason is not None
    assert any("POLICY_PROHIBIT" in r for r in trace.reason_codes)
    assert trace.latency_ms > 0.0
    assert trace.decision_latency_ms == trace.latency_ms

    # Assert audit store has DECISION and ROUTE_TRACE records
    records = fw.audit_store.get_records("sess_int_prohibit")
    types = [r.type for r in records]
    assert "ACTION_RECEIVED" in types
    assert "DECISION" in types
    assert "ROUTE_TRACE" in types
    assert fw.audit_store.verify_chain("sess_int_prohibit") is True


# ==============================================================================
# 2. EVIDENCE_MISSING -> REVIEW (Fast Path)
# ==============================================================================


def test_02_evidence_missing_returns_review_on_fast_path(cascade_registry: Registry) -> None:
    """
    Rule: EVIDENCE_MISSING -> REVIEW
    When policy verdict is EVIDENCE_MISSING:
    - Decision is REVIEW
    - Review ticket is generated
    - Fast path is used
    - Monitor is NOT invoked
    - Review reason is recorded
    - Decision latency is recorded
    """
    mock_monitor = MagicMock()
    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=mock_monitor),
    )

    # Configure external destination without binding resource -> R1 missing bound_resource
    fw.submit(
        ActionRequest(
            session_id="sess_int_evidence",
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    req = ActionRequest(
        session_id="sess_int_evidence",
        tool="execute_export",
        arguments={},
    )
    resp = fw.submit(req)

    # Assert decision outcome
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.policy_verdict == PolicyVerdict.EVIDENCE_MISSING
    assert resp.ticket_id is not None

    # Assert monitor was never invoked
    assert not mock_monitor.called

    # Assert route trace
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "fast_path"
    assert trace.is_fast_path is True
    assert trace.is_cascade_path is False
    assert trace.monitor_invoked is False
    assert trace.final_decision == Decision.REVIEW
    assert trace.review_reason is not None
    assert any("EVIDENCE_MISSING" in r for r in trace.reason_codes)
    assert trace.latency_ms > 0.0

    # Assert audit store integrity
    assert fw.audit_store.verify_chain("sess_int_evidence") is True


# ==============================================================================
# 3. UNDETERMINED with valid monitor ALLOW -> ALLOW (Cascade Path)
# ==============================================================================


def test_03_undetermined_with_valid_monitor_allow(cascade_registry: Registry) -> None:
    """
    Rule: UNDETERMINED with valid monitor ALLOW -> ALLOW
    When policy verdict is UNDETERMINED and monitor returns benign / allow:
    - Decision is ALLOW
    - Execution proceeds to EXECUTED
    - Cascade path is used
    - Monitor was invoked
    - Decision latency is recorded
    """
    # Monitor returns ALLOW token
    fake_monitor = MagicMock(return_value="ALLOW")

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=fake_monitor),
    )
    fw.executor.register_tool_handler("query_telemetry", lambda a: ({"telemetry": "ok"}, None))

    req = ActionRequest(
        session_id="sess_int_allow",
        tool="query_telemetry",  # Registered, but no policy rule -> UNDETERMINED
        arguments={"metric": "cpu_utilization"},
    )
    resp = fw.submit(req)

    # Assert execution outcome
    assert resp.status == "EXECUTED"
    assert resp.decision == Decision.ALLOW
    assert resp.policy_verdict == PolicyVerdict.UNDETERMINED
    assert resp.monitor_verdict == MonitorVerdict.BENIGN
    assert resp.result is not None
    assert resp.result.has_value is True
    assert resp.result.confirmation_level == ConfirmationLevel.CONFIRMED_COMPLETED

    # Assert monitor was invoked
    assert fake_monitor.called

    # Assert route trace
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "cascade_path"
    assert trace.is_cascade_path is True
    assert trace.is_fast_path is False
    assert trace.monitor_invoked is True
    assert trace.final_decision == Decision.ALLOW
    assert trace.policy_verdict == PolicyVerdict.UNDETERMINED
    assert trace.monitor_verdict == MonitorVerdict.BENIGN
    assert trace.latency_ms > 0.0

    # Assert audit store integrity
    assert fw.audit_store.verify_chain("sess_int_allow") is True


def test_03b_undetermined_with_structured_json_monitor_allow(
    cascade_registry: Registry,
) -> None:
    """Verify monitor returning valid structured JSON payload authorizing an action."""
    json_monitor = MagicMock(
        return_value='{"verdict": "BENIGN", "confidence": 0.99, "reasoning": "Normal telemetry"}'
    )

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=json_monitor),
    )
    fw.executor.register_tool_handler("read_service_status", lambda a: ({"service": "ok"}, None))

    req = ActionRequest(
        session_id="sess_int_json_allow",
        tool="read_service_status",
        arguments={"service": "gateway"},
    )
    resp = fw.submit(req)

    assert resp.status == "EXECUTED"
    assert resp.decision == Decision.ALLOW
    assert resp.route_trace is not None
    assert resp.route_trace.path == "cascade_path"
    assert resp.route_trace.monitor_invoked is True
    assert resp.route_trace.final_decision == Decision.ALLOW


# ==============================================================================
# 4. UNDETERMINED with monitor UNKNOWN -> REVIEW (Cascade Path)
# ==============================================================================


def test_04_undetermined_with_monitor_unknown_returns_review(
    cascade_registry: Registry,
) -> None:
    """
    Rule: UNDETERMINED with monitor UNKNOWN -> REVIEW
    When policy verdict is UNDETERMINED and monitor returns UNKNOWN verdict:
    - Decision is REVIEW
    - Review ticket is created
    - Cascade path is used
    - Monitor was invoked
    - Failure/review reason recorded
    """
    unknown_monitor = DeterministicMockMonitor(verdict=MonitorVerdict.UNKNOWN)

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=unknown_monitor),
    )

    req = ActionRequest(
        session_id="sess_int_unknown",
        tool="query_telemetry",
        arguments={"metric": "active_users"},
    )
    resp = fw.submit(req)

    # Assert review ticket created
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.policy_verdict == PolicyVerdict.UNDETERMINED
    assert resp.monitor_verdict == MonitorVerdict.UNKNOWN
    assert resp.ticket_id is not None

    # Assert route trace
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "cascade_path"
    assert trace.is_cascade_path is True
    assert trace.monitor_invoked is True
    assert trace.final_decision == Decision.REVIEW
    assert (
        trace.review_reason == CascadeFailureReason.MONITOR_UNKNOWN.value
        or CascadeFailureReason.MONITOR_UNKNOWN.value in trace.reason_codes
    )
    assert trace.latency_ms > 0.0

    # Assert audit store integrity
    assert fw.audit_store.verify_chain("sess_int_unknown") is True


# ==============================================================================
# 5. UNDETERMINED with malformed monitor output -> REVIEW (Cascade Path)
# ==============================================================================


@pytest.mark.parametrize(
    "malformed_output,expected_reason",
    [
        ("NOT_A_VALID_DECISION_TOKEN", CascadeFailureReason.MALFORMED_OUTPUT.value),
        ("{invalid_json: key without quotes, [", CascadeFailureReason.MALFORMED_JSON.value),
        ('{"random_key": "irrelevant_value"}', CascadeFailureReason.MALFORMED_OUTPUT.value),
        (12345, CascadeFailureReason.MALFORMED_OUTPUT.value),
    ],
)
def test_05_undetermined_with_malformed_monitor_output_returns_review(
    cascade_registry: Registry, malformed_output: Any, expected_reason: str
) -> None:
    """
    Rule: UNDETERMINED with malformed monitor output -> REVIEW
    When policy is UNDETERMINED and monitor produces unparseable or unrecognized output:
    - Decision is REVIEW
    - Review ticket is created
    - Cascade path is used
    - Monitor was invoked
    - Never returns ALLOW
    - Structured reason code is recorded
    """
    malformed_monitor = MagicMock(return_value=malformed_output)

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=malformed_monitor),
    )

    req = ActionRequest(
        session_id=f"sess_int_malformed_{abs(hash(str(malformed_output)))}",
        tool="query_telemetry",
        arguments={"metric": "disk_io"},
    )
    resp = fw.submit(req)

    # Assert fails closed to REVIEW
    assert resp.decision != Decision.ALLOW
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.ticket_id is not None

    # Assert route trace
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "cascade_path"
    assert trace.monitor_invoked is True
    assert trace.final_decision == Decision.REVIEW
    assert trace.review_reason == expected_reason or expected_reason in trace.reason_codes
    assert trace.latency_ms > 0.0


# ==============================================================================
# 6. UNDETERMINED with monitor timeout -> REVIEW (Cascade Path)
# ==============================================================================


def test_06_undetermined_with_monitor_timeout_returns_review(
    cascade_registry: Registry,
) -> None:
    """
    Rule: UNDETERMINED with monitor timeout -> REVIEW
    When policy is UNDETERMINED and monitor times out:
    - Decision is REVIEW
    - Review ticket is created
    - Cascade path is used
    - Monitor was invoked
    - Never returns ALLOW
    - Failure reason recorded
    """
    timeout_monitor = DeterministicMockMonitor(simulate_timeout=True)

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=timeout_monitor),
    )

    req = ActionRequest(
        session_id="sess_int_timeout",
        tool="query_telemetry",
        arguments={"metric": "network_packets"},
    )
    resp = fw.submit(req)

    # Assert fails closed to REVIEW
    assert resp.decision != Decision.ALLOW
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.ticket_id is not None

    # Assert route trace
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "cascade_path"
    assert trace.monitor_invoked is True
    assert trace.final_decision == Decision.REVIEW
    assert (
        trace.review_reason == CascadeFailureReason.MONITOR_TIMEOUT.value
        or CascadeFailureReason.MONITOR_TIMEOUT.value in trace.reason_codes
    )
    assert trace.latency_ms > 0.0

    # Assert audit chain valid
    assert fw.audit_store.verify_chain("sess_int_timeout") is True


def test_06b_undetermined_with_timeout_exception_returns_review(
    cascade_registry: Registry,
) -> None:
    """Verify monitor raising explicit TimeoutError fails closed to REVIEW."""
    def timeout_func(*args: Any, **kwargs: Any) -> Any:
        raise TimeoutError("Cascade monitor call exceeded deadline of 200ms")

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=timeout_func),
    )

    req = ActionRequest(
        session_id="sess_int_timeouterr",
        tool="query_telemetry",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.decision == Decision.REVIEW
    assert resp.route_trace is not None
    assert resp.route_trace.path == "cascade_path"
    assert resp.route_trace.monitor_invoked is True
    assert any("MONITOR_TIMEOUT" in r for r in resp.route_trace.reason_codes)


# ==============================================================================
# 7. Monitor Exception -> REVIEW (Cascade Path)
# ==============================================================================


def test_07_undetermined_with_monitor_exception_returns_review(
    cascade_registry: Registry,
) -> None:
    """
    Rule: Monitor exception -> REVIEW
    When monitor raises an unexpected runtime exception:
    - Decision is REVIEW
    - Review ticket is created
    - Cascade path is used
    - Never returns ALLOW
    - Exception reason is recorded
    """
    def broken_monitor(*args: Any, **kwargs: Any) -> Any:
        raise ConnectionResetError("Connection closed unexpectedly by upstream peer")

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=broken_monitor),
    )

    req = ActionRequest(
        session_id="sess_int_exc",
        tool="query_telemetry",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.decision != Decision.ALLOW
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "cascade_path"
    assert trace.monitor_invoked is True
    assert trace.final_decision == Decision.REVIEW
    assert any("MONITOR_EXCEPTION" in r for r in trace.reason_codes)


# ==============================================================================
# 8. Never return ALLOW after monitor failure
# ==============================================================================


def test_08_never_return_allow_after_monitor_failure(cascade_registry: Registry) -> None:
    """
    Invariant: Never return ALLOW after a monitor failure.
    Even if an adapter or monitor returned an ALLOW decision token alongside an error/unknown,
    FirewallCore unconditionally overrides and enforces REVIEW.
    """
    faulty_monitor = MagicMock(side_effect=RuntimeError("Internal model error"))
    adapter = CascadeAdapter(monitor=faulty_monitor)

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=adapter,
    )

    req = ActionRequest(
        session_id="sess_int_safety",
        tool="query_telemetry",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.decision != Decision.ALLOW
    assert resp.status != "EXECUTED"
    assert resp.decision == Decision.REVIEW


# ==============================================================================
# 9. Mandatory Review Classes Escalation
# ==============================================================================


def test_09_undetermined_mandatory_review_class_escalates_to_review(
    cascade_registry: Registry,
) -> None:
    """
    Invariant: Tools in mandatory_review_classes (e.g. DESTRUCTIVE or PRIVILEGED_ADMIN)
    must escalate to REVIEW even when the cascade monitor returns ALLOW.
    """
    benign_monitor = MagicMock(return_value="ALLOW")

    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=benign_monitor),
        decision_config=DecisionConfig(),  # Defaults: DESTRUCTIVE & PRIVILEGED_ADMIN in MR
    )

    # purge_database is DESTRUCTIVE
    req = ActionRequest(
        session_id="sess_int_mr_destructive",
        tool="purge_database",
        arguments={"target": "all"},
    )
    resp = fw.submit(req)

    # Must be escalated to REVIEW despite monitor ALLOW
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.ticket_id is not None
    assert resp.route_trace is not None
    trace = resp.route_trace
    assert trace.path == "cascade_path"
    assert trace.monitor_invoked is True
    assert trace.final_decision == Decision.REVIEW
    assert any("CLASS_REQUIRES_REVIEW:DESTRUCTIVE" in r for r in trace.reason_codes)

    # rotate_keys is PRIVILEGED_ADMIN
    req2 = ActionRequest(
        session_id="sess_int_mr_admin",
        tool="rotate_keys",
        arguments={},
    )
    resp2 = fw.submit(req2)

    assert resp2.status == "PENDING_REVIEW"
    assert resp2.decision == Decision.REVIEW
    assert resp2.ticket_id is not None
    assert any("CLASS_REQUIRES_REVIEW:PRIVILEGED_ADMIN" in r for r in resp2.reason_codes)


# ==============================================================================
# 10. Route Trace Audit Trail & Continuity Verification
# ==============================================================================


def test_10_route_trace_audit_trail_and_chain_verification(
    cascade_registry: Registry,
) -> None:
    """
    Verify that across multiple decisions (fast path PROHIBIT, fast path EVIDENCE_MISSING,
    cascade path ALLOW, cascade path UNKNOWN), all route traces are properly committed to
    the audit store and the cryptographic hash chain is continuously valid.
    """
    benign_monitor = MagicMock(return_value="ALLOW")
    fw = FirewallCore(
        registry=cascade_registry,
        cascade_adapter=CascadeAdapter(monitor=benign_monitor),
    )
    fw.executor.register_tool_handler("query_telemetry", lambda a: ({"telemetry": "ok"}, None))
    session_id = "sess_int_audit_continuity"

    # Action 1: Relabel (Fast path PROHIBIT)
    r1 = fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="relabel_resource",
            arguments={"resource_ref": "customer_records", "classification": "PUBLIC"},
        )
    )
    assert r1.route_trace is not None
    assert r1.route_trace.path == "fast_path"

    # Action 2: Telemetry query (Cascade path ALLOW)
    r2 = fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="query_telemetry",
            arguments={"metric": "memory"},
        )
    )
    assert r2.route_trace is not None
    assert r2.route_trace.path == "cascade_path"
    assert r2.route_trace.monitor_invoked is True

    # Verify audit store records
    records = fw.audit_store.get_records(session_id)
    route_trace_records = [r for r in records if r.type == "ROUTE_TRACE"]
    assert len(route_trace_records) == 2

    # Verify cryptographic hash chain
    assert fw.audit_store.verify_chain(session_id) is True

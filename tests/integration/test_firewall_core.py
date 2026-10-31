"""
Integration and security regression tests for FirewallCore runtime (Phase 3).
Verifies the complete vertical slice from request interception to controlled execution:
1. Permitted action follows complete authorization path
2. Prohibited action denied even when monitor returns BENIGN (INV-03)
3. Missing required evidence results in REVIEW (INV-04)
4. Unregistered tool is denied (INV-04)
5. Unknown monitor verdict fails closed (INV-04)
6. Malformed monitor output fails closed (INV-04)
7. Monitor exceptions and timeouts do not result in ALLOW (INV-04)
8. Pending review blocks subsequent actions in the same session (BUSY, D-17)
9. Invalid or mismatched token cannot execute an action (INV-06)
10. Consumed token cannot be reused (INV-06)
11. Concurrent attempts to redeem the same token cannot execute twice (INV-06)
12. Duplicate review approval cannot trigger duplicate execution (INV-05)
13. Audit records remain valid and verified across successful and failed decisions (INV-09)
14. State or action mismatches invalidate authorization (INV-06, INV-12)
"""

import concurrent.futures

import pytest

from firewall.contracts.enums import (
    ConfirmationLevel,
    Decision,
    MonitorVerdict,
    PolicyVerdict,
    ScoreKind,
)
from firewall.contracts.models import ActionRequest, CanonicalAction
from firewall.core import FirewallCore
from firewall.decision.combinator import DecisionConfig
from firewall.executor.tokens import (
    TokenStore,
)
from firewall.monitor.mock import DeterministicMockMonitor
from firewall.state.evidence import HmacEvidenceVerifier
from firewall.state.registry import Registry


@pytest.fixture
def test_registry() -> Registry:
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
            "select_resource": {"tool_class": "READ_SENSITIVE"},
            "create_export_job": {"tool_class": "WRITE_INTERNAL"},
            "configure_destination": {"tool_class": "WRITE_INTERNAL"},
            "execute_export": {"tool_class": "EGRESS_EXTERNAL"},
            "validate_schema": {"tool_class": "READ_LOW"},
            "relabel_resource": {"tool_class": "PRIVILEGED_ADMIN"},
        },
    )


@pytest.fixture
def firewall(test_registry: Registry) -> FirewallCore:
    return FirewallCore(registry=test_registry)


def test_01_permitted_action_complete_path(firewall: FirewallCore):
    """Case 1: A permitted action follows the complete authorization path."""
    req = ActionRequest(
        session_id="sess_test_01",
        tool="validate_schema",
        arguments={},
    )
    resp = firewall.submit(req)

    assert resp.status == "EXECUTED"
    assert resp.decision == Decision.ALLOW
    assert resp.policy_verdict == PolicyVerdict.PERMIT
    assert resp.result is not None
    assert resp.result.has_value is True
    assert resp.result.confirmation_level == ConfirmationLevel.CONFIRMED_COMPLETED

    # Check state sequence advanced
    audit_records = firewall.audit_store.get_records("sess_test_01")
    assert len(audit_records) >= 2  # ACTION_RECEIVED, DECISION


def test_02_prohibited_action_denied_despite_benign_monitor(test_registry: Registry):
    """Case 2: A prohibited action is denied even when a monitor returns BENIGN (INV-03)."""
    # Configure an aggressive benign monitor
    benign_monitor = DeterministicMockMonitor(
        verdict=MonitorVerdict.BENIGN,
        score=0.01,
        score_kind=ScoreKind.HEURISTIC_RISK,
    )
    fw = FirewallCore(
        registry=test_registry,
        monitor=benign_monitor,
        decision_config=DecisionConfig(monitor_authority="escalate_only"),
    )

    # First setup state: select confidential resource and external destination
    # We can submit directly to setup state
    fw.submit(
        ActionRequest(
            session_id="sess_test_02",
            tool="select_resource",
            arguments={"resource_ref": "customer_records"},
        )
    )
    fw.submit(
        ActionRequest(
            session_id="sess_test_02",
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    # Now attempt prohibited execute_export (R1)
    req = ActionRequest(
        session_id="sess_test_02",
        tool="execute_export",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.status == "DENIED"
    assert resp.decision == Decision.DENY
    assert resp.policy_verdict == PolicyVerdict.PROHIBIT
    assert any("POLICY_PROHIBIT:R1" in r for r in resp.reason_codes)


def test_03_missing_required_evidence_results_in_review(test_registry: Registry):
    """Case 3: Missing required evidence results in REVIEW (INV-04)."""
    fw = FirewallCore(registry=test_registry)

    # Destination is configured, but no resource is bound
    fw.submit(
        ActionRequest(
            session_id="sess_test_03",
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    # R1 needs bound_resource.classification to know if it's confidential -> EVIDENCE_MISSING
    req = ActionRequest(
        session_id="sess_test_03",
        tool="execute_export",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.policy_verdict == PolicyVerdict.EVIDENCE_MISSING
    assert resp.ticket_id is not None
    assert any("EVIDENCE_MISSING" in r for r in resp.reason_codes)


def test_04_unregistered_tool_denied(firewall: FirewallCore):
    """Case 4: An unregistered tool is denied fail-closed."""
    req = ActionRequest(
        session_id="sess_test_04",
        tool="malicious_unregistered_tool",
        arguments={"cmd": "rm -rf /"},
    )
    resp = firewall.submit(req)

    assert resp.status == "DENIED"
    assert resp.decision == Decision.DENY
    assert any("UNKNOWN_TOOL:malicious_unregistered_tool" in r for r in resp.reason_codes)


def test_05_unknown_monitor_verdict_fails_closed(test_registry: Registry):
    """Case 5: An unknown monitor verdict fails closed to REVIEW (INV-04)."""
    unknown_monitor = DeterministicMockMonitor(verdict=MonitorVerdict.UNKNOWN)
    fw = FirewallCore(
        registry=test_registry,
        monitor=unknown_monitor,
        decision_config=DecisionConfig(monitor_authority="escalate_only"),
    )

    # Action validate_schema is PERMIT by policy
    req = ActionRequest(
        session_id="sess_test_05",
        tool="validate_schema",
        arguments={},
    )
    resp = fw.submit(req)

    # Under escalate_only, UNKNOWN monitor verdict escalates to REVIEW
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.monitor_verdict == MonitorVerdict.UNKNOWN


def test_06_malformed_monitor_output_fails_closed(test_registry: Registry):
    """Case 6: Malformed monitor output fails closed to UNKNOWN -> REVIEW."""

    class MalformedMonitor:
        monitor_id = "malformed_monitor"
        version = "0.1.0"

        def assess(self, view, *, timeout_ms=None):
            raise ValueError("Malformed model JSON: Unterminated string at line 1")

    fw = FirewallCore(
        registry=test_registry,
        monitor=MalformedMonitor(),  # SafeMonitorWrapper catches and maps to UNKNOWN
        decision_config=DecisionConfig(monitor_authority="escalate_only"),
    )

    req = ActionRequest(
        session_id="sess_test_06",
        tool="validate_schema",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.monitor_verdict == MonitorVerdict.UNKNOWN


def test_07_monitor_exceptions_and_timeouts_never_allow(test_registry: Registry):
    """Case 7: Monitor exceptions and timeouts do not result in ALLOW (INV-04)."""
    timeout_monitor = DeterministicMockMonitor(simulate_timeout=True)
    fw = FirewallCore(
        registry=test_registry,
        monitor=timeout_monitor,
        decision_config=DecisionConfig(monitor_authority="escalate_only"),
    )

    req = ActionRequest(
        session_id="sess_test_07",
        tool="validate_schema",
        arguments={},
    )
    resp = fw.submit(req)

    assert resp.decision != Decision.ALLOW
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW


def test_08_pending_review_blocks_subsequent_actions(test_registry: Registry):
    """Case 8: A pending review blocks subsequent actions in the same session (BUSY, D-17)."""
    fw = FirewallCore(registry=test_registry)

    # Destination configured, unselected resource -> execute_export triggers REVIEW
    fw.submit(
        ActionRequest(
            session_id="sess_test_08",
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )
    resp1 = fw.submit(ActionRequest(session_id="sess_test_08", tool="execute_export", arguments={}))
    assert resp1.status == "PENDING_REVIEW"
    assert resp1.ticket_id is not None

    # Immediate second action while review is pending MUST return BUSY
    resp2 = fw.submit(
        ActionRequest(session_id="sess_test_08", tool="validate_schema", arguments={})
    )
    assert resp2.status == "BUSY"
    assert "BUSY:PENDING_REVIEW" in resp2.reason_codes


def test_09_invalid_or_mismatched_token_rejected():
    """Case 9: An invalid or mismatched token cannot execute an action (INV-06)."""
    token_store = TokenStore()
    verifier = HmacEvidenceVerifier(key=b"test_key")
    from firewall.executor.executor import ControlledExecutor

    executor = ControlledExecutor(token_store=token_store, verifier=verifier)

    token = token_store.issue_token(
        action_id="act_real_1",
        action_hash="hash_real_1",
        state_head_hash="head_real_1",
        decision_id="dec_1",
    )

    # Attempt execution with mismatched action_id
    mismatched_action = CanonicalAction(
        action_id="act_FORGED",
        session_id="sess_01",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash="hash_real_1",
    )

    envelope, receipt = executor.execute(token, mismatched_action, "head_real_1")
    assert envelope.has_value is False
    assert envelope.error is not None
    assert envelope.error["code"] == "TOKEN_ERROR"
    assert "mismatch" in envelope.error["message"]


def test_10_consumed_token_cannot_be_reused():
    """Case 10: A consumed token cannot be reused (INV-06)."""
    token_store = TokenStore()
    verifier = HmacEvidenceVerifier(key=b"test_key")
    from firewall.executor.executor import ControlledExecutor

    executor = ControlledExecutor(token_store=token_store, verifier=verifier)

    token = token_store.issue_token(
        action_id="act_1",
        action_hash="hash_1",
        state_head_hash="head_1",
        decision_id="dec_1",
    )

    action = CanonicalAction(
        action_id="act_1",
        session_id="sess_01",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash="hash_1",
    )

    # First execution succeeds
    env1, _ = executor.execute(token, action, "head_1")
    assert env1.has_value is True

    # Second execution with same token FAILS (TOKEN_REUSED)
    env2, _ = executor.execute(token, action, "head_1")
    assert env2.has_value is False
    assert env2.error is not None
    assert "single-use violation" in env2.error["message"]


def test_11_concurrent_token_redemption_executes_only_once():
    """Case 11: Concurrent attempts to redeem the same token cannot execute twice (INV-06)."""
    token_store = TokenStore()
    verifier = HmacEvidenceVerifier(key=b"test_key")
    from firewall.executor.executor import ControlledExecutor

    executor = ControlledExecutor(token_store=token_store, verifier=verifier)

    token = token_store.issue_token(
        action_id="act_conc_1",
        action_hash="hash_conc_1",
        state_head_hash="head_conc_1",
        decision_id="dec_conc_1",
    )

    action = CanonicalAction(
        action_id="act_conc_1",
        session_id="sess_conc",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash="hash_conc_1",
    )

    results = []

    def try_redeem():
        return executor.execute(token, action, "head_conc_1")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(try_redeem) for _ in range(8)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    successes = [env for env, _ in results if env.has_value is True]
    failures = [env for env, _ in results if env.has_value is False]

    # Exactly ONE thread must succeed!
    assert len(successes) == 1
    assert len(failures) == 7
    assert all("single-use violation" in f.error["message"] for f in failures)


def test_12_duplicate_review_approval_cannot_execute_twice(test_registry: Registry):
    """Case 12: Duplicate review approval cannot trigger duplicate execution (INV-05)."""
    fw = FirewallCore(registry=test_registry)

    # Trigger REVIEW
    fw.submit(
        ActionRequest(
            session_id="sess_test_12",
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )
    resp = fw.submit(ActionRequest(session_id="sess_test_12", tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    ticket_id = resp.ticket_id

    # Resolve review: FIRST APPROVAL -> EXECUTED
    res1 = fw.resolve_review(ticket_id=ticket_id, outcome="APPROVE", reviewer_id="reviewer_alice")
    assert res1.status == "EXECUTED"
    assert res1.decision == Decision.ALLOW

    # Duplicate resolution attempt MUST FAIL
    res2 = fw.resolve_review(ticket_id=ticket_id, outcome="APPROVE", reviewer_id="reviewer_alice")
    assert res2.status == "FAILED"
    assert any("already in state" in r or "REVIEW_ERROR" in r for r in res2.reason_codes)


def test_13_audit_records_verified_continuity(firewall: FirewallCore):
    """Case 13: Audit records remain valid across decisions (INV-09)."""
    session_id = "sess_test_13"

    # Sequence of multiple actions: permit, deny, invalid
    firewall.submit(ActionRequest(session_id=session_id, tool="validate_schema", arguments={}))
    firewall.submit(
        ActionRequest(
            session_id=session_id,
            tool="relabel_resource",
            arguments={"resource_ref": "x", "classification": "PUBLIC"},
        )
    )
    firewall.submit(ActionRequest(session_id=session_id, tool="unknown_bad_tool", arguments={}))

    # Verify cryptographic hash chain
    assert firewall.audit_store.verify_chain(session_id) is True

    records = firewall.audit_store.get_records(session_id)
    assert len(records) >= 6
    assert all(r.session_id == session_id for r in records)


def test_14_state_head_mismatch_invalidates_authorization():
    """Case 14: State head mismatch invalidates authorization token redemption."""
    token_store = TokenStore()
    verifier = HmacEvidenceVerifier(key=b"test_key")
    from firewall.executor.executor import ControlledExecutor

    executor = ControlledExecutor(token_store=token_store, verifier=verifier)

    token = token_store.issue_token(
        action_id="act_14",
        action_hash="hash_14",
        state_head_hash="expected_head_A",
        decision_id="dec_14",
    )

    action = CanonicalAction(
        action_id="act_14",
        session_id="sess_14",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash="hash_14",
    )

    # State head drifted from expected_head_A to drifted_head_B before execution
    env, _ = executor.execute(token, action, "drifted_head_B")
    assert env.has_value is False
    assert "state_head_hash mismatch" in env.error["message"]


def test_15_review_approval_re_evaluates_policy_prohibit(test_registry: Registry) -> None:
    """Case 15: If policy evaluates to PROHIBIT upon review approval, execution is denied."""
    from firewall.contracts.enums import Classification, Zone
    from firewall.contracts.models import DestinationRef, ResourceRef

    fw = FirewallCore(registry=test_registry)
    session_id = "sess_15_re_eval"

    resp = fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="execute_export",
            arguments={},
        )
    )
    assert resp.status == "PENDING_REVIEW"
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    # Simulate state transition making the action PROHIBIT before review approval
    state = fw._get_state(session_id)
    fw._states[session_id] = state.model_copy(
        update={
            "bound_resource": ResourceRef(
                ref="customer_records",
                classification=Classification.CONFIDENTIAL,
                selected_seq=1,
            ),
            "destination": DestinationRef(ref="external_storage", zone=Zone.EXTERNAL),
        }
    )

    res_resp = fw.resolve_review(ticket_id, "APPROVE", "alice")
    assert res_resp.status == "DENIED"
    assert res_resp.decision == Decision.DENY
    assert any("POLICY_PROHIBIT_ON_APPROVAL" in r for r in res_resp.reason_codes)


def test_16_executor_verifier_key_synchronized_with_core(test_registry: Registry) -> None:
    """Case 16: Custom executor verifier key is automatically synchronized with core."""
    from firewall.executor.executor import ControlledExecutor

    custom_key = b"custom_secret_key_32_bytes_long_"
    token_store = TokenStore()
    custom_verifier = HmacEvidenceVerifier(key=custom_key)
    executor = ControlledExecutor(token_store=token_store, verifier=custom_verifier)

    fw = FirewallCore(registry=test_registry, executor=executor)
    assert fw.verifier._key == custom_key


def test_17_review_ticket_natural_expiration_clears_busy() -> None:
    """Case 17: Natural expiration of review ticket unlocks the session from BUSY."""
    from firewall.contracts.models import ReviewerView
    from firewall.oversight.service import ReviewService

    review_service = ReviewService()
    session_id = "sess_17_expiry"
    action = CanonicalAction(
        action_id="act_17",
        session_id=session_id,
        seq=1,
        tool="execute_export",
        arguments={},
        action_hash="hash_17",
    )
    summary = ReviewerView(
        tool="execute_export",
        typed_arguments={},
        policy_verdict=PolicyVerdict.UNDETERMINED,
        reason_codes=["MANDATORY_REVIEW"],
        state_facts={},
    )
    _ = review_service.create_ticket(action, summary, ttl_ms=100, now_ms=1000)
    assert review_service.has_pending_review(session_id, now_ms=1050) is True
    # At time 1150 (past 1000 + 100 = 1100), ticket is naturally expired
    assert review_service.has_pending_review(session_id, now_ms=1150) is False


def test_18_execute_export_without_destination_records_anomaly(test_registry: Registry) -> None:
    """Case 18: Implicit execute_export without destination records UNKNOWN_DESTINATION."""
    from firewall.contracts.models import StateEventEnvelope
    from firewall.state.engine import apply_event, initial_state

    session_id = "sess_18_no_dest"
    state = initial_state(session_id)
    envelope = StateEventEnvelope(
        session_id=session_id,
        seq=1,
        prior_head=state.head_hash,
        event_type="EXECUTED",
        action_id="act_18",
        token_id="tok_18",
        payload={"tool": "execute_export", "arguments": {"rows": 100}},
    )
    new_state = apply_event(
        state=state,
        event=envelope,
        registry=test_registry,
        expected_session_id=session_id,
    )
    assert "UNKNOWN_DESTINATION" in new_state.anomalies
    assert new_state.indeterminate_state > 0

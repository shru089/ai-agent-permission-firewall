"""
Characterization tests for newly agreed AASF decision and review-revalidation semantics:
1. UNDETERMINED + BENIGN must produce REVIEW, not ALLOW.
2. PROHIBIT must always produce DENY, even if the monitor is BENIGN or a reviewer approves.
3. Reviewer approval must revalidate current policy and state freshness before issuing
   an execution authorization token.
4. A stale review approval must never directly execute an action.
"""

import pytest

from firewall.contracts.enums import (
    Decision,
    EventType,
    MonitorVerdict,
    PolicyVerdict,
    ToolClass,
)
from firewall.contracts.models import (
    ActionRequest,
    CanonicalAction,
    StateEventEnvelope,
)
from firewall.core import FirewallCore
from firewall.decision.combinator import DecisionConfig, decide
from firewall.executor.executor import ControlledExecutor
from firewall.executor.tokens import TokenStore
from firewall.state.engine import apply_event
from firewall.state.registry import Registry


@pytest.fixture
def test_registry() -> Registry:
    return Registry(
        resources={
            "customer_records": {"classification": "CONFIDENTIAL", "rows": 5000},
            "public_records": {"classification": "PUBLIC", "rows": 800},
            "other_records": {"classification": "PUBLIC", "rows": 500},
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
        },
    )


def test_undetermined_plus_benign_results_in_review():
    """
    Agreed semantic 1: UNDETERMINED + BENIGN must produce REVIEW, not ALLOW.
    Characterization test: Currently, combinator returns ALLOW when monitor is BENIGN
    for tools not in mandatory_review_classes. Under agreed semantics, it must produce REVIEW.
    """
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    decision, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert decision == Decision.REVIEW, (
        f"Expected REVIEW for UNDETERMINED + BENIGN, but got {decision}. "
        f"Current combinator allows benign monitors to grant ALLOW on undetermined policy."
    )


def test_prohibit_plus_benign_results_in_deny():
    """
    Agreed semantic 2: PROHIBIT must always produce DENY, even if monitor is BENIGN.
    Characterization test: Verifies that PROHIBIT supremacy holds unconditionally
    over BENIGN monitor.
    """
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    decision, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PROHIBIT,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
        matched_rules=["R1-no-confidential-external-export"],
    )
    assert decision == Decision.DENY, (
        f"Expected DENY for PROHIBIT + BENIGN, got {decision}."
    )
    assert any("POLICY_PROHIBIT" in r for r in reasons), (
        f"Expected POLICY_PROHIBIT reason code, got {reasons}."
    )


def test_reviewer_cannot_override_prohibition(test_registry: Registry):
    """
    Agreed semantic 2: PROHIBIT must always produce DENY, even if a reviewer approves.
    Characterization test: A reviewer attempting to approve a ticket for an action that
    evaluates to PROHIBIT under current policy must not execute and must yield DENY.
    """
    fw = FirewallCore(registry=test_registry)
    session_id = "sess_review_prohibit"

    # Step 1: Configure destination to EXTERNAL
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    # Step 2: execute_export without resource bound enters PENDING_REVIEW (EVIDENCE_MISSING)
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

    # Step 3: Session state now has CONFIDENTIAL resource bound, making export
    # strictly PROHIBIT under R1
    s_curr = fw._get_state(session_id)
    env_bound = StateEventEnvelope(
        session_id=session_id,
        seq=s_curr.seq + 1,
        prior_head=s_curr.head_hash,
        event_type=EventType.EXECUTED.value,
        action_id="act_bind_conf",
        token_id="tok_bind_conf",
        payload={"tool": "select_resource", "arguments": {"resource_ref": "customer_records"}},
    )
    fw._states[session_id] = apply_event(
        s_curr, env_bound, fw.registry, expected_session_id=session_id
    )

    # Step 4: Reviewer approves the ticket
    resolve_resp = fw.resolve_review(
        ticket_id=ticket_id,
        outcome="APPROVE",
        reviewer_id="reviewer_alice",
    )

    # Agreed semantics: Reviewer approval cannot override policy prohibition.
    # Must revalidate policy, reject execution, and produce DENY.
    assert resolve_resp.status != "EXECUTED", (
        "Action was executed despite policy PROHIBIT! Reviewer bypassed prohibition."
    )
    assert resolve_resp.decision == Decision.DENY, (
        f"Expected decision DENY when reviewer approves prohibited action, "
        f"got {resolve_resp.decision}."
    )


def test_review_approval_revalidates_changed_state(test_registry: Registry):
    """
    Agreed semantic 3: Reviewer approval must revalidate current policy and state freshness
    before issuing an execution authorization token.
    Characterization test: If state changed between ticket creation and approval,
    the review approval must revalidate against the fresh state and not directly execute.
    """
    fw = FirewallCore(registry=test_registry)
    session_id = "sess_review_changed_state"

    # Step 1: Configure destination
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    # Step 2: execute_export enters PENDING_REVIEW
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

    # Step 3: Session state advances while review is pending (state transition occurred)
    s_curr = fw._get_state(session_id)
    env_advance = StateEventEnvelope(
        session_id=session_id,
        seq=s_curr.seq + 1,
        prior_head=s_curr.head_hash,
        event_type=EventType.EXECUTED.value,
        action_id="act_state_advance",
        token_id="tok_state_advance",
        payload={"tool": "select_resource", "arguments": {"resource_ref": "other_records"}},
    )
    fw._states[session_id] = apply_event(
        s_curr, env_advance, fw.registry, expected_session_id=session_id
    )

    # Step 4: Reviewer approves the ticket
    resolve_resp = fw.resolve_review(
        ticket_id=ticket_id,
        outcome="APPROVE",
        reviewer_id="reviewer_bob",
    )

    # Agreed semantics: Approval must detect state change and revalidate rather
    # than blindly executing
    assert resolve_resp.status != "EXECUTED", (
        "Action was directly executed despite session state changing during review!"
    )


def test_stale_review_approval_cannot_execute():
    """
    Agreed semantic 4: A stale review approval must never directly execute an action.
    Characterization test: An authorization token issued from an approval bound to an earlier
    state head must be rejected by ControlledExecutor when session state has advanced.
    """
    token_store = TokenStore()
    executor = ControlledExecutor(token_store=token_store)

    action = CanonicalAction(
        action_id="act_stale_review_1",
        session_id="sess_stale_review",
        seq=1,
        tool="execute_export",
        arguments={},
        action_hash="hash_stale_review_1",
    )

    # Review approval issues an authorization token bound to state head H0 at approval time
    stale_state_head = "head_hash_approval_time_H0"
    token = token_store.issue_token(
        action_id=action.action_id,
        action_hash=action.action_hash,
        state_head_hash=stale_state_head,
        decision_id="dec_approved_1",
    )

    # Before execution occurs, the state head advances to H1
    current_state_head = "head_hash_advanced_time_H1"

    envelope, receipt = executor.execute(
        token=token,
        action=action,
        current_state_head=current_state_head,
    )

    # ControlledExecutor must reject the stale authorization token and not execute
    assert envelope.has_value is False, "Stale review approval token was executed!"
    assert envelope.error is not None
    assert envelope.error["code"] == "TOKEN_ERROR"
    assert "state_head_hash mismatch" in envelope.error["message"]

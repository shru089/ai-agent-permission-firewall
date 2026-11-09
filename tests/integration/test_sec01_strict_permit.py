"""
Integration tests for SEC-01: Strict PERMIT-Only Execution After Human Approval.

Verifies that under strict Zero-Trust review enforcement (strict_permit_on_approval=True):
1. EVIDENCE_MISSING on review approval fails closed to DENY; executor is NEVER called.
2. UNDETERMINED on review approval fails closed to DENY; executor is NEVER called.
3. PROHIBIT on review approval fails closed to DENY; executor is NEVER called.
4. UNKNOWN_TOOL on review approval fails closed to DENY; executor is NEVER called.
5. Strict PERMIT with fresh state executes successfully; executor is invoked exactly once.
"""

from typing import Any, Optional

import pytest

from firewall.contracts.enums import (
    Classification,
    Decision,
    MonitorVerdict,
    PolicyVerdict,
    ToolClass,
    Zone,
)
from firewall.contracts.models import (
    ActionRequest,
    CanonicalAction,
    DestinationRef,
    EvidenceReceipt,
    ResourceRef,
    ResultEnvelope,
    ReviewerView,
)
from firewall.core import FirewallCore
from firewall.decision.combinator import DecisionConfig
from firewall.executor.executor import ControlledExecutor
from firewall.executor.tokens import TokenStore
from firewall.monitor.mock import DeterministicMockMonitor
from firewall.state.evidence import HmacEvidenceVerifier
from firewall.state.registry import Registry


class ExecutorSpy(ControlledExecutor):
    """Spy on ControlledExecutor to prove exact execution invocation counts."""

    def __init__(self, token_store: TokenStore, verifier: HmacEvidenceVerifier):
        super().__init__(token_store=token_store, verifier=verifier)
        self.call_count = 0
        self.executed_actions: list[CanonicalAction] = []

    def execute(
        self,
        token: Any,
        action: CanonicalAction,
        current_state_head: str,
        now_ms: Optional[int] = None,
    ) -> tuple[ResultEnvelope, Optional[EvidenceReceipt]]:
        self.call_count += 1
        self.executed_actions.append(action)
        return super().execute(
            token=token,
            action=action,
            current_state_head=current_state_head,
            now_ms=now_ms,
        )


@pytest.fixture
def spy_firewall() -> tuple[FirewallCore, ExecutorSpy]:
    registry = Registry(
        resources={
            "confidential_data": {"classification": "CONFIDENTIAL", "rows": 1000},
            "public_data": {"classification": "PUBLIC", "rows": 500},
        },
        destinations={
            "external_cloud": {"zone": "EXTERNAL"},
            "internal_store": {"zone": "INTERNAL"},
        },
        tools={
            "select_resource": {"tool_class": "READ_SENSITIVE"},
            "create_export_job": {"tool_class": "WRITE_INTERNAL"},
            "configure_destination": {"tool_class": "WRITE_INTERNAL"},
            "execute_export": {"tool_class": "EGRESS_EXTERNAL"},
            "custom_cleanup_tool": {"tool_class": "DESTRUCTIVE"},
        },
    )
    token_store = TokenStore()
    verifier = HmacEvidenceVerifier(key=b"test_secret_key_32_bytes_long_123")
    spy_executor = ExecutorSpy(token_store=token_store, verifier=verifier)
    # Require review for EGRESS_EXTERNAL so legitimate PERMIT actions enter review
    cfg = DecisionConfig(mandatory_review_classes=(ToolClass.EGRESS_EXTERNAL,))

    # Monitor configured to return SUSPICIOUS to ensure review routing
    monitor = DeterministicMockMonitor(verdict=MonitorVerdict.SUSPICIOUS)

    fw = FirewallCore(
        registry=registry,
        executor=spy_executor,
        verifier=verifier,
        token_store=token_store,
        decision_config=cfg,
        monitor=monitor,
        strict_permit_on_approval=True,  # SEC-01 Hardened Mode
    )
    return fw, spy_executor


def test_sec01_evidence_missing_never_invokes_executor(
    spy_firewall: tuple[FirewallCore, ExecutorSpy]
) -> None:
    """SEC-01 Case 1: EVIDENCE_MISSING upon approval fails closed; executor is NEVER invoked."""
    fw, spy = spy_firewall
    session_id = "sess_sec01_missing_evidence"

    # Configure external destination without selecting a resource (bound_resource is missing)
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_cloud"},
        )
    )

    # execute_export has missing evidence for bound_resource -> PENDING_REVIEW
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    assert resp.policy_verdict == PolicyVerdict.EVIDENCE_MISSING
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    calls_before = spy.call_count

    # Reviewer attempts to approve the ticket without required evidence
    resolve_resp = fw.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="alice")

    assert resolve_resp.status == "DENIED"
    assert resolve_resp.decision == Decision.DENY
    assert resolve_resp.policy_verdict == PolicyVerdict.EVIDENCE_MISSING
    assert any("EVIDENCE_MISSING_ON_APPROVAL" in r for r in resolve_resp.reason_codes)

    # PROVE: ControlledExecutor was NEVER invoked during review approval!
    assert spy.call_count == calls_before


def test_sec01_undetermined_policy_never_invokes_executor(
    spy_firewall: tuple[FirewallCore, ExecutorSpy]
) -> None:
    """SEC-01 Case 2: UNDETERMINED policy upon approval fails closed; executor is NEVER invoked."""
    fw, spy = spy_firewall
    session_id = "sess_sec01_undetermined"

    # custom_cleanup_tool is not matched by any policy rules -> policy is UNDETERMINED
    # DESTRUCTIVE requires review and monitor is SUSPICIOUS -> submit() yields PENDING_REVIEW
    resp = fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="custom_cleanup_tool",
            arguments={},
        )
    )
    assert resp.status == "PENDING_REVIEW"
    assert resp.policy_verdict == PolicyVerdict.UNDETERMINED
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    calls_before = spy.call_count

    # Reviewer approves ticket with UNDETERMINED policy
    resolve_resp = fw.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="bob")

    assert resolve_resp.status == "DENIED"
    assert resolve_resp.decision == Decision.DENY
    assert resolve_resp.policy_verdict == PolicyVerdict.UNDETERMINED
    assert any("POLICY_UNDETERMINED_ON_APPROVAL" in r for r in resolve_resp.reason_codes)

    # PROVE: ControlledExecutor was NEVER invoked during review approval!
    assert spy.call_count == calls_before


def test_sec01_prohibit_never_invokes_executor(
    spy_firewall: tuple[FirewallCore, ExecutorSpy]
) -> None:
    """SEC-01 Case 3: PROHIBIT policy upon approval fails closed; executor is NEVER invoked."""
    fw, spy = spy_firewall
    session_id = "sess_sec01_prohibit"

    # Select public data, configure external storage -> goes to review
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="select_resource",
            arguments={"resource_ref": "public_data"},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="create_export_job",
            arguments={},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_cloud"},
        )
    )
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    # Before approval, state is altered so bound resource is CONFIDENTIAL (PROHIBIT by Rule R1)
    state = fw._get_state(session_id)
    fw._states[session_id] = state.model_copy(
        update={
            "bound_resource": ResourceRef(
                ref="confidential_data",
                classification=Classification.CONFIDENTIAL,
                selected_seq=1,
            ),
            "destination": DestinationRef(ref="external_cloud", zone=Zone.EXTERNAL),
        }
    )
    # Keep recorded head aligned to isolate policy check
    fw._ticket_state_heads[ticket_id] = fw._get_state(session_id).head_hash

    calls_before = spy.call_count

    # Reviewer attempts approval on prohibited action
    resolve_resp = fw.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="charlie")

    assert resolve_resp.status == "DENIED"
    assert resolve_resp.decision == Decision.DENY
    assert resolve_resp.policy_verdict == PolicyVerdict.PROHIBIT
    assert any("POLICY_PROHIBIT_ON_APPROVAL" in r for r in resolve_resp.reason_codes)

    # PROVE: ControlledExecutor was NEVER invoked during review approval!
    assert spy.call_count == calls_before


def test_sec01_unknown_tool_never_invokes_executor(
    spy_firewall: tuple[FirewallCore, ExecutorSpy]
) -> None:
    """SEC-01 Case 4: UNKNOWN_TOOL upon approval fails closed; executor is NEVER invoked."""
    fw, spy = spy_firewall
    session_id = "sess_sec01_unknown_tool"

    canonical_action = CanonicalAction(
        action_id="act_unknown_01",
        session_id=session_id,
        seq=1,
        tool="unregistered_malicious_tool",
        arguments={},
        action_hash="0" * 64,
    )
    reviewer_view = ReviewerView(
        tool="unregistered_malicious_tool",
        typed_arguments={},
        policy_verdict=PolicyVerdict.UNDETERMINED,
        reason_codes=["UNKNOWN_TOOL"],
        state_facts={},
    )
    ticket = fw.review_service.create_ticket(
        action=canonical_action,
        summary=reviewer_view,
    )
    ticket_id = ticket.ticket_id
    fw._actions_by_id[canonical_action.action_id] = canonical_action
    fw._ticket_state_heads[ticket_id] = fw._get_state(session_id).head_hash

    calls_before = spy.call_count

    resolve_resp = fw.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="dave")

    assert resolve_resp.status == "DENIED"
    assert resolve_resp.decision == Decision.DENY
    assert any("UNKNOWN_TOOL" in r for r in resolve_resp.reason_codes)

    # PROVE: ControlledExecutor was NEVER invoked during review approval!
    assert spy.call_count == calls_before


def test_sec01_legitimate_permit_executes_exactly_once(
    spy_firewall: tuple[FirewallCore, ExecutorSpy]
) -> None:
    """SEC-01 Case 5: Legitimate PERMIT with fresh state executes successfully (1 invocation)."""
    fw, spy = spy_firewall
    session_id = "sess_sec01_legit"

    # Setup valid prerequisites for export of public data
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="select_resource",
            arguments={"resource_ref": "public_data"},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="create_export_job",
            arguments={},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_cloud"},
        )
    )

    # execute_export evaluates to PERMIT, but is held in PENDING_REVIEW because EGRESS_EXTERNAL
    # is in mandatory_review_classes
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    assert resp.policy_verdict == PolicyVerdict.PERMIT
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    calls_before = spy.call_count

    # Reviewer approves legitimate PERMIT action
    resolve_resp = fw.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="eve")

    assert resolve_resp.status == "EXECUTED"
    assert resolve_resp.decision == Decision.ALLOW
    assert resolve_resp.result is not None

    # PROVE: ControlledExecutor was invoked EXACTLY ONCE on review approval!
    assert spy.call_count == calls_before + 1
    assert len(spy.executed_actions) == calls_before + 1
    assert spy.executed_actions[-1].tool == "execute_export"

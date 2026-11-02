"""
Unit tests for Read-Only Audit Viewer and Human Review Queue Dashboard (Phase 9).
"""

import pytest

from firewall.audit.store import AuditStore
from firewall.contracts.enums import PolicyVerdict, ReviewStatus
from firewall.contracts.models import CanonicalAction, ReviewerView
from firewall.dashboard.viewer import DashboardManager
from firewall.oversight.service import (
    ReviewService,
    TicketAlreadyResolvedError,
    TicketNotFoundError,
)


@pytest.fixture
def sample_setup():
    audit_store = AuditStore()
    review_service = ReviewService()
    manager = DashboardManager(audit_store, review_service)
    return audit_store, review_service, manager


def test_audit_viewer_read_only_immutability(sample_setup):
    audit_store, _, manager = sample_setup

    audit_store.append("sess_1", "ACTION_REQUEST", {"tool": "read_data"})
    audit_store.append("sess_1", "GATEWAY_DECISION", {"decision": "ALLOW"})

    records = manager.viewer.get_records("sess_1")
    assert len(records) == 2
    assert manager.viewer.verify_session_integrity("sess_1") is True

    # Mutating returned record in-place must NOT corrupt the underlying store
    records[0].payload["tool"] = "TAMPERED"

    internal_records = audit_store.get_records("sess_1")
    assert internal_records[0].payload["tool"] == "read_data"
    assert manager.viewer.verify_session_integrity("sess_1") is True


def test_review_queue_ticket_lifecycle_and_binding(sample_setup):
    _, review_service, manager = sample_setup

    action = CanonicalAction(
        action_id="act_101",
        session_id="sess_oversight",
        seq=1,
        tool="execute_export",
        arguments={"batch": 10},
        action_hash="hash_act_101",
    )
    summary = ReviewerView(
        tool="execute_export",
        typed_arguments={"batch": 10},
        policy_verdict=PolicyVerdict.EVIDENCE_MISSING,
        reason_codes=["MANDATORY_REVIEW"],
    )

    ticket = review_service.create_ticket(action, summary)
    assert ticket.status == ReviewStatus.PENDING

    # Review queue sees ticket
    pending = manager.queue.get_pending_tickets()
    assert len(pending) == 1
    assert pending[0].ticket_id == ticket.ticket_id
    assert pending[0].action_id == "act_101"

    # Resolving ticket updates status
    resolved = manager.queue.resolve_ticket(
        ticket_id=ticket.ticket_id,
        outcome="APPROVE",
        reviewer_id="human_analyst_01",
    )
    assert resolved.status == ReviewStatus.APPROVED
    assert resolved.resolved_by == "human_analyst_01"

    # Ticket is no longer pending
    assert len(manager.queue.get_pending_tickets()) == 0

    # Attempting to re-resolve the same ticket raises TicketAlreadyResolvedError
    with pytest.raises(TicketAlreadyResolvedError):
        manager.queue.resolve_ticket(
            ticket_id=ticket.ticket_id,
            outcome="REJECT",
            reviewer_id="human_analyst_02",
        )


def test_review_queue_cannot_resolve_unknown_ticket(sample_setup):
    _, _, manager = sample_setup
    with pytest.raises(TicketNotFoundError):
        manager.queue.resolve_ticket(
            ticket_id="tkt_nonexistent",
            outcome="APPROVE",
            reviewer_id="analyst",
        )


def test_dashboard_cli_and_html_rendering(sample_setup):
    audit_store, review_service, manager = sample_setup
    audit_store.append("sess_ui", "ACTION_SUBMITTED", {"tool": "query"})

    action = CanonicalAction(
        action_id="act_ui_1",
        session_id="sess_ui",
        seq=1,
        tool="modify_record",
        arguments={"id": 42},
        action_hash="hash_act_ui_1",
    )
    summary = ReviewerView(
        tool="modify_record",
        typed_arguments={"id": 42},
        policy_verdict=PolicyVerdict.UNDETERMINED,
        reason_codes=["SUSPICIOUS"],
    )
    review_service.create_ticket(action, summary)

    cli_text = manager.render_cli_summary()
    assert "Total Audit Trail Records: 1" in cli_text
    assert "Active Pending Review Tickets: 1" in cli_text
    assert "act_ui_1" in cli_text

    html_text = manager.export_html_report()
    assert "<!DOCTYPE html>" in html_text
    assert "act_ui_1" in html_text
    assert "modify_record" in html_text

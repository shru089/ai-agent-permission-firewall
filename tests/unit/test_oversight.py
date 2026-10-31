"""
Unit tests for human oversight and review ticket service (C8).
Verifies:
- Ticket creation, pending state tracking, resolution
- Prevention of duplicate resolution and duplicate execution
- Expiration handling
"""

import pytest

from firewall.contracts.enums import PolicyVerdict, ReviewStatus
from firewall.contracts.hashing import compute_action_hash
from firewall.contracts.models import CanonicalAction, ReviewerView
from firewall.oversight.service import (
    ReviewError,
    ReviewService,
    TicketAlreadyResolvedError,
    TicketExpiredError,
)


@pytest.fixture
def review_service() -> ReviewService:
    return ReviewService()


@pytest.fixture
def sample_action() -> CanonicalAction:
    return CanonicalAction(
        action_id="act_review_1",
        session_id="sess_rev_1",
        seq=1,
        tool="execute_export",
        arguments={},
        action_hash=compute_action_hash("sess_rev_1", 1, "execute_export", {}),
    )


@pytest.fixture
def sample_summary() -> ReviewerView:
    return ReviewerView(
        tool="execute_export",
        typed_arguments={},
        policy_verdict=PolicyVerdict.UNDETERMINED,
        reason_codes=["EVIDENCE_MISSING"],
        state_facts={},
    )


def test_ticket_creation_and_pending_check(
    review_service: ReviewService,
    sample_action: CanonicalAction,
    sample_summary: ReviewerView,
):
    assert review_service.has_pending_review("sess_rev_1") is False

    ticket = review_service.create_ticket(
        action=sample_action,
        summary=sample_summary,
        ttl_ms=60_000,
        now_ms=1000,
    )

    assert ticket.status == ReviewStatus.PENDING
    assert ticket.action_id == "act_review_1"
    assert review_service.has_pending_review("sess_rev_1") is True

    pending = review_service.get_pending_ticket_for_session("sess_rev_1")
    assert pending is not None
    assert pending.ticket_id == ticket.ticket_id


def test_ticket_resolution_approve_and_reject(
    review_service: ReviewService,
    sample_action: CanonicalAction,
    sample_summary: ReviewerView,
):
    ticket = review_service.create_ticket(sample_action, sample_summary)

    # Resolve as APPROVE
    resolved = review_service.resolve_ticket(
        ticket_id=ticket.ticket_id,
        outcome="APPROVE",
        reviewer_id="rev_bob",
        now_ms=2000,
    )

    assert resolved.status == ReviewStatus.APPROVED
    assert resolved.resolved_by == "rev_bob"
    assert resolved.resolved_ms == 2000
    assert review_service.has_pending_review("sess_rev_1") is False

    # Attempting to resolve again raises TicketAlreadyResolvedError
    with pytest.raises(TicketAlreadyResolvedError):
        review_service.resolve_ticket(ticket.ticket_id, "APPROVE", "rev_bob")


def test_ticket_mark_executed(
    review_service: ReviewService,
    sample_action: CanonicalAction,
    sample_summary: ReviewerView,
):
    ticket = review_service.create_ticket(sample_action, sample_summary)
    review_service.resolve_ticket(ticket.ticket_id, "APPROVE", "rev_bob")

    # Mark executed
    executed_ticket = review_service.mark_executed(ticket.ticket_id)
    assert executed_ticket.status == ReviewStatus.EXECUTED

    # Duplicate mark_executed raises ReviewError
    with pytest.raises(ReviewError, match="duplicate execution"):
        review_service.mark_executed(ticket.ticket_id)


def test_ticket_expiration(
    review_service: ReviewService,
    sample_action: CanonicalAction,
    sample_summary: ReviewerView,
):
    ticket = review_service.create_ticket(sample_action, sample_summary, ttl_ms=1000, now_ms=1000)

    with pytest.raises(TicketExpiredError):
        review_service.resolve_ticket(ticket.ticket_id, "APPROVE", "rev_bob", now_ms=2001)

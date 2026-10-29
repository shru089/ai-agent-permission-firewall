"""
Human Oversight and Review Ticket Lifecycle Service (C8) for AI Agent Permission Firewall.
Enforces:
- Single in-flight action per session: pending review blocks subsequent session actions (BUSY).
- Prevents duplicate approvals or duplicate executions from the same ticket.
- Preserves audit traceability for reviewer decisions.
Source: 05_TECHNICAL_SPEC.md §3.2, §5, 01_THREAT_MODEL.md (INV-05)
"""

import threading
import time
import uuid
from typing import Optional

from firewall.contracts.enums import ReviewStatus
from firewall.contracts.models import CanonicalAction, ReviewerView, ReviewTicket


class ReviewError(Exception):
    """Base exception for review lifecycle errors."""


class TicketNotFoundError(ReviewError):
    """Raised when review ticket ID does not exist."""


class TicketAlreadyResolvedError(ReviewError):
    """Raised when attempting to resolve a ticket that is not in PENDING state."""


class TicketExpiredError(ReviewError):
    """Raised when resolving an expired ticket."""


class ReviewService:
    """
    Thread-safe human oversight review service managing ticket lifecycle.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tickets: dict[str, ReviewTicket] = {}
        # session_id -> ticket_id of current pending ticket
        self._pending_by_session: dict[str, str] = {}

    def create_ticket(
        self,
        action: CanonicalAction,
        summary: ReviewerView,
        ttl_ms: int = 300_000,
        now_ms: Optional[int] = None,
    ) -> ReviewTicket:
        """Create a new pending review ticket for an action requiring oversight."""
        curr_time = now_ms if now_ms is not None else int(time.time() * 1000)
        ticket_id = f"tkt_{uuid.uuid4().hex[:12]}"

        ticket = ReviewTicket(
            ticket_id=ticket_id,
            action_id=action.action_id,
            action_hash=action.action_hash,
            created_ms=curr_time,
            expires_ms=curr_time + ttl_ms,
            status=ReviewStatus.PENDING,
            summary=summary,
        )

        with self._lock:
            self._tickets[ticket_id] = ticket
            self._pending_by_session[action.session_id] = ticket_id

        return ticket

    def resolve_ticket(
        self,
        ticket_id: str,
        outcome: str,
        reviewer_id: str,
        now_ms: Optional[int] = None,
    ) -> ReviewTicket:
        """
        Resolve a pending review ticket as APPROVED or REJECTED.
        Thread-safe; prevents duplicate resolution.
        """
        curr_time = now_ms if now_ms is not None else int(time.time() * 1000)
        outcome_upper = outcome.strip().upper()
        if outcome_upper not in ("APPROVE", "REJECT", "APPROVED", "REJECTED"):
            raise ValueError(f"Invalid review outcome '{outcome}'. Expected 'APPROVE' or 'REJECT'")

        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise TicketNotFoundError(f"Review ticket '{ticket_id}' not found")

            # Check expiration
            if curr_time > ticket.expires_ms:
                ticket.status = ReviewStatus.EXPIRED
                raise TicketExpiredError(
                    f"Review ticket '{ticket_id}' expired at {ticket.expires_ms}"
                )

            # Check status is PENDING
            if ticket.status != ReviewStatus.PENDING:
                raise TicketAlreadyResolvedError(
                    f"Review ticket '{ticket_id}' is already in state '{ticket.status.value}'"
                )

            new_status = (
                ReviewStatus.APPROVED
                if outcome_upper in ("APPROVE", "APPROVED")
                else ReviewStatus.REJECTED
            )
            updated_ticket = ticket.model_copy(
                update={
                    "status": new_status,
                    "resolved_by": reviewer_id,
                    "resolved_ms": curr_time,
                }
            )
            self._tickets[ticket_id] = updated_ticket

            # Clear session pending pointer if it points to this ticket
            for sid, t_id in list(self._pending_by_session.items()):
                if t_id == ticket_id:
                    del self._pending_by_session[sid]

            return updated_ticket

    def mark_executed(self, ticket_id: str) -> ReviewTicket:
        """Mark an approved review ticket as executed to prevent duplicate execution."""
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise TicketNotFoundError(f"Review ticket '{ticket_id}' not found")

            if ticket.status == ReviewStatus.EXECUTED:
                raise ReviewError(
                    f"Ticket '{ticket_id}' was already executed (duplicate execution prevented)"
                )

            if ticket.status != ReviewStatus.APPROVED:
                raise ReviewError(
                    f"Cannot execute ticket '{ticket_id}' in state '{ticket.status.value}' "
                    f"(must be APPROVED)"
                )

            updated = ticket.model_copy(update={"status": ReviewStatus.EXECUTED})
            self._tickets[ticket_id] = updated
            return updated

    def has_pending_review(self, session_id: str) -> bool:
        """Check if session has an active pending review ticket (D-17)."""
        with self._lock:
            t_id = self._pending_by_session.get(session_id)
            if t_id is None:
                return False
            t = self._tickets.get(t_id)
            if t is None or t.status != ReviewStatus.PENDING:
                self._pending_by_session.pop(session_id, None)
                return False
            return True

    def get_pending_ticket_for_session(self, session_id: str) -> Optional[ReviewTicket]:
        """Get the current pending ticket for a session if any."""
        with self._lock:
            t_id = self._pending_by_session.get(session_id)
            if not t_id:
                return None
            return self._tickets.get(t_id)

    def get_ticket(self, ticket_id: str) -> Optional[ReviewTicket]:
        """Look up ticket by ID."""
        with self._lock:
            return self._tickets.get(ticket_id)

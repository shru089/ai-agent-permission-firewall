"""
Read-Only Audit Viewer and Review Queue Manager for AI Agent Permission Firewall.

Enforces:
- INV-09: Immutability of cryptographic audit trail records (read-only views, chain verification).
- INV-04 / INV-05: Review tickets strictly bound to canonical action digests and session state;
  cannot approve an action other than its bound ticket.
"""

from __future__ import annotations

import copy
import html
from typing import List, Optional

from firewall.audit.store import AuditRecord, AuditStore
from firewall.contracts.models import ReviewTicket
from firewall.oversight.service import (
    ReviewService,
)


class AuditViewer:
    """
    Read-only audit trail viewer providing cryptographic integrity verification and search.
    """

    def __init__(self, audit_store: AuditStore) -> None:
        self._audit_store = audit_store

    def get_records(
        self,
        session_id: Optional[str] = None,
        record_type: Optional[str] = None,
    ) -> List[AuditRecord]:
        """
        Returns deep copies of audit records to prevent in-place tampering.
        """
        raw_records = self._audit_store.get_records(session_id)

        if record_type is not None:
            raw_records = [r for r in raw_records if r.type == record_type]

        # Return deep copies so external mutation does not affect internal audit store
        return [copy.deepcopy(r) for r in raw_records]

    def verify_session_integrity(self, session_id: str) -> bool:
        """
        Cryptographically verifies the hash-chain integrity of a session's audit trail.
        """
        return self._audit_store.verify_chain(session_id)

    def total_records_count(self) -> int:
        """Returns total count of audit records."""
        return len(self._audit_store.get_records())


class ReviewQueue:
    """
    Human oversight review queue manager.
    Strictly guarantees that reviewers can only resolve active bound review tickets.
    """

    def __init__(self, review_service: ReviewService) -> None:
        self._review_service = review_service

    def get_pending_tickets(self) -> List[ReviewTicket]:
        """Returns list of all currently pending review tickets."""
        return self._review_service.get_pending_tickets()

    def get_ticket(self, ticket_id: str) -> Optional[ReviewTicket]:
        """Retrieves a specific review ticket."""
        return self._review_service.get_ticket(ticket_id)

    def resolve_ticket(
        self,
        ticket_id: str,
        outcome: str,
        reviewer_id: str,
        now_ms: Optional[int] = None,
    ) -> ReviewTicket:
        """
        Resolves a review ticket with approval or denial.
        Guarantees that the decision is bound strictly to the ticket's action.
        """
        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("Reviewer ID must be non-empty")

        return self._review_service.resolve_ticket(
            ticket_id=ticket_id,
            outcome=outcome,
            reviewer_id=reviewer_id,
            now_ms=now_ms,
        )


class DashboardManager:
    """
    Unified manager for audit trail viewing and human review queue operations.
    """

    def __init__(self, audit_store: AuditStore, review_service: ReviewService) -> None:
        self.viewer = AuditViewer(audit_store)
        self.queue = ReviewQueue(review_service)

    def render_cli_summary(self) -> str:
        """Generates plain-text CLI dashboard summary."""
        pending = self.queue.get_pending_tickets()
        total_audit = self.viewer.total_records_count()

        lines = [
            "==================================================",
            "   AI AGENT PERMISSION FIREWALL - DASHBOARD       ",
            "==================================================",
            f"Total Audit Trail Records: {total_audit}",
            f"Active Pending Review Tickets: {len(pending)}",
            "--------------------------------------------------",
        ]

        if pending:
            lines.append("PENDING REVIEW TICKETS:")
            for tkt in pending:
                lines.append(
                    f"  - Ticket ID: {tkt.ticket_id} | Action ID: {tkt.action_id} | "
                    f"Tool: {tkt.summary.tool} | Status: {tkt.status.value}"
                )
        else:
            lines.append("No review tickets currently pending.")

        lines.append("==================================================")
        return "\n".join(lines)

    def export_html_report(self) -> str:
        """Generates standalone HTML report of audit trail and oversight status."""
        pending = self.queue.get_pending_tickets()
        records = self.viewer.get_records()

        pending_rows = (
            "".join(
                f"<tr><td>{html.escape(t.ticket_id)}</td><td>{html.escape(t.action_id)}</td>"
                f"<td>{html.escape(t.summary.tool)}</td><td>{html.escape(t.status.value)}</td></tr>"
                for t in pending
            )
            or "<tr><td colspan='4'>No pending review tickets</td></tr>"
        )

        audit_rows = (
            "".join(
                f"<tr><td>{r.rec_id}</td><td>{r.seq}</td><td>{html.escape(r.session_id)}</td>"
                f"<td>{html.escape(r.type)}</td><td><code>{html.escape(r.hash[:16])}...</code></td></tr>"
                for r in records[-50:]  # Latest 50 records
            )
            or "<tr><td colspan='5'>No audit records</td></tr>"
        )

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AI Agent Permission Firewall Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 2rem; background: #f8fafc; color: #1e293b;
        }}
        h1, h2 {{ color: #0f172a; }}
        table {{
            width: 100%; border-collapse: collapse; margin-bottom: 2rem;
            background: white; border-radius: 8px; overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{
            background: #f1f5f9; font-weight: 600; font-size: 0.875rem;
            text-transform: uppercase; letter-spacing: 0.05em;
        }}
        code {{
            background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px;
            font-size: 0.85em; font-family: monospace;
        }}
    </style>
</head>
<body>
    <h1>AI Agent Permission Firewall — Oversight & Audit</h1>
    <h2>Pending Review Queue ({len(pending)})</h2>
    <table>
        <thead>
            <tr><th>Ticket ID</th><th>Action ID</th><th>Tool</th><th>Status</th></tr>
        </thead>
        <tbody>
            {pending_rows}
        </tbody>
    </table>
    <h2>Recent Audit Records (Total: {len(records)})</h2>
    <table>
        <thead>
            <tr><th>Record ID</th><th>Seq</th><th>Session ID</th><th>Type</th><th>Hash</th></tr>
        </thead>
        <tbody>
            {audit_rows}
        </tbody>
    </table>
</body>
</html>"""

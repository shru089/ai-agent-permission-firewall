"""
Central In-Process Orchestration Component (C1): FirewallCore.
Coordinates request interception, session locks, state folding, policy evaluation,
monitor consultation, pure decision combination, single-use token authorization,
controlled execution, and hash-chained audit logging.

Source: 05_TECHNICAL_SPEC.md §1, §3, §5, §10, 08_IMPLEMENTATION_ROADMAP.md Phase 3,
        01_THREAT_MODEL.md (INV-01 through INV-12)
"""

import threading
import time
import uuid
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from firewall.audit.store import AuditStore
from firewall.contracts.enums import (
    Decision,
    EventType,
    MonitorVerdict,
    PolicyVerdict,
)
from firewall.contracts.hashing import compute_action_hash
from firewall.contracts.models import (
    CONTRACTS_VERSION,
    ActionRequest,
    CanonicalAction,
    DecisionRecord,
    MonitorAssessment,
    ResultEnvelope,
    SessionState,
    StateEventEnvelope,
    VersionSet,
)
from firewall.decision.combinator import DecisionConfig, decide
from firewall.executor.executor import ControlledExecutor
from firewall.executor.tokens import TokenStore
from firewall.monitor.base import Monitor, SafeMonitorWrapper
from firewall.oversight.service import ReviewError, ReviewService
from firewall.policy.evaluator import PolicyEngine, create_default_stateful_policy
from firewall.state.engine import apply_event, initial_state
from firewall.state.evidence import HmacEvidenceVerifier
from firewall.state.registry import Registry
from firewall.state.views import build_monitor_view, build_reviewer_view


class FirewallResponse(BaseModel):
    """
    Typed response returned by FirewallCore.submit() and resolve_review().
    Source: 05_TECHNICAL_SPEC.md §5
    """

    action_id: Optional[str] = None
    status: str  # "EXECUTED" | "DENIED" | "PENDING_REVIEW" | "BUSY" | "FAILED"
    decision: Optional[Decision] = None
    reason_codes: list[str] = Field(default_factory=list)
    policy_verdict: Optional[PolicyVerdict] = None
    monitor_verdict: Optional[MonitorVerdict] = None
    ticket_id: Optional[str] = None
    result: Optional[ResultEnvelope] = None

    model_config = ConfigDict(extra="forbid")


class FirewallCore:
    """
    Central In-Process Orchestration Engine (C1).
    Independent of FastAPI; callable directly by experiment harnesses or thin API adapters.
    """

    def __init__(
        self,
        registry: Registry,
        policy_engine: Optional[PolicyEngine] = None,
        monitor: Optional[Monitor] = None,
        decision_config: Optional[DecisionConfig] = None,
        audit_store: Optional[AuditStore] = None,
        token_store: Optional[TokenStore] = None,
        review_service: Optional[ReviewService] = None,
        executor: Optional[ControlledExecutor] = None,
        verifier: Optional[HmacEvidenceVerifier] = None,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine or create_default_stateful_policy()
        self.monitor = SafeMonitorWrapper(monitor) if monitor else None
        self.decision_config = decision_config or DecisionConfig()
        self.audit_store = audit_store or AuditStore()
        self.token_store = token_store or TokenStore()
        self.review_service = review_service or ReviewService()
        self.verifier = verifier or HmacEvidenceVerifier(key=b"firewall_default_key")
        self.executor = executor or ControlledExecutor(
            token_store=self.token_store, verifier=self.verifier
        )

        # Session control state
        self._global_lock = threading.Lock()
        self._session_locks: dict[str, threading.Lock] = {}
        self._states: dict[str, SessionState] = {}
        self._action_seqs: dict[str, int] = {}
        self._in_flight: set[str] = set()  # session_ids with active requests
        self._actions_by_id: dict[str, CanonicalAction] = {}

    def _get_session_lock(self, session_id: str) -> threading.Lock:
        with self._global_lock:
            if session_id not in self._session_locks:
                self._session_locks[session_id] = threading.Lock()
            return self._session_locks[session_id]

    def _get_state(self, session_id: str) -> SessionState:
        if session_id not in self._states:
            self._states[session_id] = initial_state(session_id)
        return self._states[session_id]

    def submit(self, request: ActionRequest) -> FirewallResponse:
        """
        Submit an agent action request to the firewall for authorization and execution.
        Guarantees single in-flight action per session (D-17).
        """
        session_id = request.session_id
        session_lock = self._get_session_lock(session_id)

        # 1. Non-blocking acquisition of session lock to check concurrency
        acquired = session_lock.acquire(blocking=False)
        if not acquired:
            # Another action is currently in flight for this session -> BUSY (D-17)
            return FirewallResponse(
                action_id=None,
                status="BUSY",
                decision=None,
                reason_codes=["BUSY:ACTION_IN_FLIGHT"],
            )

        try:
            # 2. Check if a human review is currently pending for this session (D-17)
            if self.review_service.has_pending_review(session_id):
                pending_ticket = self.review_service.get_pending_ticket_for_session(session_id)
                t_id = pending_ticket.ticket_id if pending_ticket else None
                return FirewallResponse(
                    action_id=None,
                    status="BUSY",
                    decision=None,
                    reason_codes=["BUSY:PENDING_REVIEW"],
                    ticket_id=t_id,
                )

            # 3. Assign monotonic action sequence and create CanonicalAction
            curr_seq = self._action_seqs.get(session_id, 0) + 1
            self._action_seqs[session_id] = curr_seq
            action_id = f"act_{uuid.uuid4().hex[:12]}"
            action_hash = compute_action_hash(session_id, curr_seq, request.tool, request.arguments)

            canonical_action = CanonicalAction(
                action_id=action_id,
                session_id=session_id,
                seq=curr_seq,
                tool=request.tool,
                arguments=request.arguments,
                action_hash=action_hash,
            )
            self._actions_by_id[action_id] = canonical_action

            # Record ACTION_RECEIVED in audit log
            self.audit_store.append(
                session_id=session_id,
                record_type="ACTION_RECEIVED",
                payload=canonical_action.model_dump(),
            )

            # 4. Validate tool registration
            tool_info = self.registry.get_tool(request.tool)
            if tool_info is None:
                # Unregistered tool: fail-closed with DENY (INV-04)
                dec, reasons = decide(
                    valid=False,
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    validation_error=f"UNKNOWN_TOOL:{request.tool}",
                    config=self.decision_config,
                )
                self._record_decision_audit(
                    canonical_action,
                    self._get_state(session_id),
                    dec,
                    reasons,
                    PolicyVerdict.UNDETERMINED,
                    MonitorVerdict.NOT_CONSULTED,
                )
                self._apply_terminal_event(session_id, canonical_action, EventType.ACTION_DENIED)
                return FirewallResponse(
                    action_id=action_id,
                    status="DENIED",
                    decision=dec,
                    reason_codes=reasons,
                    policy_verdict=PolicyVerdict.UNDETERMINED,
                    monitor_verdict=MonitorVerdict.NOT_CONSULTED,
                )

            # 5. Obtain current state
            state = self._get_state(session_id)

            # 6. Evaluate deterministic policy rules
            t_policy_start = time.perf_counter_ns()
            policy_result = self.policy_engine.evaluate(canonical_action, state, self.registry)
            t_policy_ms = (time.perf_counter_ns() - t_policy_start) / 1_000_000.0

            # 7. Monitor consultation rule
            monitor_verdict = MonitorVerdict.NOT_CONSULTED
            monitor_assessment: Optional[MonitorAssessment] = None
            should_consult_monitor = False

            if self.monitor is not None:
                if self.decision_config.monitor_authority == "escalate_only":
                    should_consult_monitor = policy_result.verdict == PolicyVerdict.PERMIT
                elif self.decision_config.monitor_authority == "decide_undetermined":
                    should_consult_monitor = policy_result.verdict == PolicyVerdict.UNDETERMINED

            if should_consult_monitor and self.monitor is not None:
                monitor_view = build_monitor_view(
                    monitor_type=self.monitor.monitor_id,
                    action=canonical_action,
                    state=state,
                    registry=self.registry,
                )
                monitor_assessment = self.monitor.assess(monitor_view)
                monitor_verdict = monitor_assessment.verdict

            # 8. Deterministic Decision Combinator
            t_decide_start = time.perf_counter_ns()
            decision, reason_codes = decide(
                valid=True,
                policy_verdict=policy_result.verdict,
                monitor_verdict=monitor_verdict,
                tool_class=tool_info.tool_class,
                config=self.decision_config,
                matched_rules=policy_result.matched_rules,
                missing_fields=policy_result.missing_fields,
            )
            t_decide_ms = (time.perf_counter_ns() - t_decide_start) / 1_000_000.0

            # 9. Record Decision in Audit Store
            self._record_decision_audit(
                canonical_action,
                state,
                decision,
                reason_codes,
                policy_result.verdict,
                monitor_verdict,
                timings={"policy": t_policy_ms, "decide": t_decide_ms},
            )

            # 10. Process Decision Outcome
            if decision == Decision.ALLOW:
                # Issue single-use authorization token
                decision_id = f"dec_{uuid.uuid4().hex[:12]}"
                token = self.token_store.issue_token(
                    action_id=action_id,
                    action_hash=action_hash,
                    state_head_hash=state.head_hash,
                    decision_id=decision_id,
                )

                # Execute via ControlledExecutor
                envelope, receipt = self.executor.execute(
                    token=token,
                    action=canonical_action,
                    current_state_head=state.head_hash,
                )

                if envelope.has_value:
                    # Update session state with EXECUTED event
                    self._apply_terminal_event(
                        session_id,
                        canonical_action,
                        EventType.EXECUTED,
                        token_id=token.token_id,
                        receipt=receipt,
                    )
                    return FirewallResponse(
                        action_id=action_id,
                        status="EXECUTED",
                        decision=decision,
                        reason_codes=reason_codes,
                        policy_verdict=policy_result.verdict,
                        monitor_verdict=monitor_verdict,
                        result=envelope,
                    )
                else:
                    # Execution failed
                    self._apply_terminal_event(
                        session_id, canonical_action, EventType.FAILED, token_id=token.token_id
                    )
                    return FirewallResponse(
                        action_id=action_id,
                        status="FAILED",
                        decision=decision,
                        reason_codes=reason_codes
                        + [
                            envelope.error.get("code", "EXEC_ERROR")
                            if envelope.error
                            else "EXEC_ERROR"
                        ],
                        policy_verdict=policy_result.verdict,
                        monitor_verdict=monitor_verdict,
                        result=envelope,
                    )

            elif decision == Decision.REVIEW:
                # Create review ticket
                reviewer_view = build_reviewer_view(
                    action=canonical_action,
                    policy_verdict=policy_result.verdict,
                    reason_codes=reason_codes,
                    state=state,
                    monitor_assessment=monitor_assessment,
                )
                ticket = self.review_service.create_ticket(
                    action=canonical_action,
                    summary=reviewer_view,
                )
                self.audit_store.append(
                    session_id=session_id,
                    record_type="REVIEW_CREATED",
                    payload=ticket.model_dump(),
                )
                return FirewallResponse(
                    action_id=action_id,
                    status="PENDING_REVIEW",
                    decision=decision,
                    reason_codes=reason_codes,
                    policy_verdict=policy_result.verdict,
                    monitor_verdict=monitor_verdict,
                    ticket_id=ticket.ticket_id,
                )

            else:  # Decision.DENY
                self._apply_terminal_event(session_id, canonical_action, EventType.ACTION_DENIED)
                return FirewallResponse(
                    action_id=action_id,
                    status="DENIED",
                    decision=decision,
                    reason_codes=reason_codes,
                    policy_verdict=policy_result.verdict,
                    monitor_verdict=monitor_verdict,
                )

        finally:
            session_lock.release()

    def resolve_review(
        self,
        ticket_id: str,
        outcome: str,
        reviewer_id: str,
    ) -> FirewallResponse:
        """
        Resolve a pending review ticket as APPROVE or REJECT.
        If APPROVE: executes the pending action through ControlledExecutor.
        """
        ticket = self.review_service.get_ticket(ticket_id)
        if ticket is None:
            return FirewallResponse(
                action_id=None,
                status="FAILED",
                reason_codes=["TICKET_NOT_FOUND"],
            )

        action = self._actions_by_id.get(ticket.action_id)
        if action is None:
            return FirewallResponse(
                action_id=ticket.action_id,
                status="FAILED",
                reason_codes=["ACTION_NOT_FOUND"],
            )

        session_id = action.session_id
        session_lock = self._get_session_lock(session_id)

        with session_lock:
            try:
                resolved_ticket = self.review_service.resolve_ticket(
                    ticket_id=ticket_id,
                    outcome=outcome,
                    reviewer_id=reviewer_id,
                )
            except ReviewError as re:
                return FirewallResponse(
                    action_id=action.action_id,
                    status="FAILED",
                    reason_codes=[f"REVIEW_ERROR:{re}"],
                )

            self.audit_store.append(
                session_id=session_id,
                record_type="REVIEW_RESOLVED",
                payload=resolved_ticket.model_dump(),
            )

            outcome_norm = outcome.strip().upper()
            if outcome_norm in ("APPROVE", "APPROVED"):
                state = self._get_state(session_id)
                decision_id = f"dec_rev_{uuid.uuid4().hex[:10]}"

                token = self.token_store.issue_token(
                    action_id=action.action_id,
                    action_hash=action.action_hash,
                    state_head_hash=state.head_hash,
                    decision_id=decision_id,
                )

                envelope, receipt = self.executor.execute(
                    token=token,
                    action=action,
                    current_state_head=state.head_hash,
                )

                # Mark ticket executed to prevent duplicate execution
                self.review_service.mark_executed(ticket_id)

                if envelope.has_value:
                    self._apply_terminal_event(
                        session_id,
                        action,
                        EventType.EXECUTED,
                        token_id=token.token_id,
                        receipt=receipt,
                    )
                    return FirewallResponse(
                        action_id=action.action_id,
                        status="EXECUTED",
                        decision=Decision.ALLOW,
                        reason_codes=["REVIEW_APPROVED"],
                        ticket_id=ticket_id,
                        result=envelope,
                    )
                else:
                    self._apply_terminal_event(
                        session_id, action, EventType.FAILED, token_id=token.token_id
                    )
                    return FirewallResponse(
                        action_id=action.action_id,
                        status="FAILED",
                        decision=Decision.ALLOW,
                        reason_codes=["EXECUTION_FAILED"],
                        ticket_id=ticket_id,
                        result=envelope,
                    )

            else:
                # Review rejected
                self._apply_terminal_event(session_id, action, EventType.ACTION_DENIED)
                return FirewallResponse(
                    action_id=action.action_id,
                    status="DENIED",
                    decision=Decision.DENY,
                    reason_codes=["REVIEW_REJECTED"],
                    ticket_id=ticket_id,
                )

    def _apply_terminal_event(
        self,
        session_id: str,
        action: CanonicalAction,
        event_type: EventType,
        token_id: str = "",
        receipt: Optional[Any] = None,
    ) -> None:
        """Advance session state hash-chain with an event envelope."""
        state = self._get_state(session_id)
        next_seq = state.seq + 1

        payload: dict[str, Any] = {
            "tool": action.tool,
            "arguments": action.arguments,
        }
        if receipt is not None:
            payload["evidence"] = receipt

        envelope = StateEventEnvelope(
            session_id=session_id,
            seq=next_seq,
            prior_head=state.head_hash,
            event_type=event_type.value,
            action_id=action.action_id,
            token_id=token_id,
            payload=payload,
        )

        new_state = apply_event(
            state=state,
            event=envelope,
            registry=self.registry,
            expected_session_id=session_id,
            verifier=self.verifier,
        )
        self._states[session_id] = new_state

    def _record_decision_audit(
        self,
        action: CanonicalAction,
        state: SessionState,
        decision: Decision,
        reason_codes: list[str],
        policy_verdict: PolicyVerdict,
        monitor_verdict: MonitorVerdict,
        timings: Optional[dict[str, float]] = None,
    ) -> None:
        record = DecisionRecord(
            decision_id=f"dec_{uuid.uuid4().hex[:12]}",
            action_id=action.action_id,
            action_hash=action.action_hash,
            state_head_hash=state.head_hash,
            decision=decision,
            reason_codes=reason_codes,
            evidence_refs=[],
            policy_verdict=policy_verdict,
            monitor_verdict=monitor_verdict,
            versions=VersionSet(
                contracts=CONTRACTS_VERSION,
                policy_hash=self.policy_engine.policy_hash,
                registry_hash=self.registry.version,
                firewall_config_hash="default",
            ),
            timings_ms=timings or {},
        )
        self.audit_store.append(
            session_id=action.session_id,
            record_type="DECISION",
            payload=record.model_dump(),
        )

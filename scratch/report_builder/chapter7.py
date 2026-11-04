"""
AASF Project Report - Chapter 7: Implementation.
Covers:
7.1 Development Environment and Package Structure
7.2 Repository Organization and Clean Architecture
7.3 Implementation Architecture and Interception Boundary
7.4 Runtime Firewall Core Orchestrator
7.5 Stateful Policy Engine and Three-Valued Logic
7.6 Advisory Monitor Interface and Rejection Cascade
7.7 Decision Combinator Implementation
7.8 Human Oversight and Revalidation Service
7.9 Execution Token Store and Controlled Executor
7.10 Deterministic State Folding Engine
7.11 Tamper-Evident Hash-Chained Audit Store
7.12 Implementation Traceability of Invariants INV-01 to INV-12
7.13 Technical Implementation Highlights and Code Snippets
"""

import os
from docx import Document
from styles import add_chapter_title, add_h1, add_h2, add_p, add_bullet, add_table, add_code_snippet, add_callout, add_page_break

def add_chapter7(doc: Document):
    add_chapter_title(doc, "CHAPTER 7", "IMPLEMENTATION")
    
    # 7.1 Development Environment and Package Structure
    add_h1(doc, "7.1", "Development Environment and Package Structure")
    add_p(doc,
        "The implementation of AASF is hosted in the official project repository and organized strictly under the `src/firewall/` "
        "canonical runtime tree. In compliance with modern software engineering best practices, source code is strictly decoupled "
        "from test suites (`tests/`), benchmark experimental harnesses (`experiments/`), and documentation (`docs/`). "
        "Table 7.1 details the package structure and subsystem directory mapping."
    )
    
    headers_t71 = ["Package / Directory", "Subsystem Role", "Core Modules & Components"]
    data_t71 = [
        ["src/firewall/core.py", "Central Orchestrator", "FirewallCore, RouteTrace, submit(), resolve_review()"],
        ["src/firewall/contracts/", "Data Contracts & Schemas", "models.py, enums.py, hashing.py (Pydantic v2)"],
        ["src/firewall/state/", "State Engine & History", "engine.py (apply_event), views.py, evidence.py, registry.py"],
        ["src/firewall/policy/", "Stateful ABAC Engine", "evaluator.py, rules.py, create_default_stateful_policy()"],
        ["src/firewall/decision/", "Invariant Combinator", "combinator.py (decide, DecisionConfig)"],
        ["src/firewall/cascade/", "Advisory Cascades", "adapter.py (CascadeAdapter), heuristic_cascade.py"],
        ["src/firewall/monitor/", "Advisory LLM & Wrappers", "base.py (SafeMonitorWrapper), mock.py, model_client.py"],
        ["src/firewall/oversight/", "Human Review Service", "service.py (ReviewService, ReviewTicket, revalidate)"],
        ["src/firewall/executor/", "Controlled Tool Execution", "executor.py (ControlledExecutor), tokens.py (TokenStore)"],
        ["src/firewall/audit/", "Tamper-Evident Audit", "store.py (AuditStore, hash chaining, verify_chain)"],
        ["experiments/", "Benchmark Harnesses", "generator/ (cli.py, synthesis.py), run_experiment.py"],
        ["tests/", "Automated Test Suites", "unit/, integration/, invariants, experiments; 433 tests passed in the audited run"],
    ]
    col_w_t71 = [1.8, 1.6, 2.6]
    add_table(doc, headers_t71, data_t71, "Table 7.1", "Repository Package Organization and Subsystem Directory Mapping", col_w_t71)

    # 7.2 Repository Organization and Clean Architecture
    add_h1(doc, "7.2", "Repository Organization and Clean Architecture")
    add_p(doc,
        "AASF adheres to Clean Architecture and Domain-Driven Design principles. High-level policy and decision logic do not depend "
        "on low-level database or OS drivers. Instead, all components communicate via strictly typed, immutable Pydantic v2 data models "
        "defined in `src/firewall/contracts/models.py`. Model schemas include version markers (`CONTRACTS_VERSION = '1.0.0'`) "
        "for identifying the contract version."
    )

    # 7.3 Implementation Architecture and Interception Boundary
    add_h1(doc, "7.3", "Implementation Architecture and Interception Boundary")
    add_p(doc,
        "The core entrypoint of the firewall is `FirewallCore.submit(request: ActionRequest) -> FirewallResponse`. "
        "When an agent emits an action, the call is intercepted by `FirewallCore`. Interception is non-bypassable because the agent "
        "is provided only with mock or proxy tool handles whose actual execution targets are held exclusively by `ControlledExecutor`."
    )

    # 7.4 Runtime Firewall Core Orchestrator
    add_h1(doc, "7.4", "Runtime Firewall Core Orchestrator")
    add_p(doc,
        "The `FirewallCore` class coordinates runtime subsystems under a session lock (`threading.Lock`) (INV-11). Listing 7.1 demonstrates the primary "
        "request submission and routing logic from `src/firewall/core.py`."
    )
    
    code_snippet_core = (
        "class FirewallCore:\n"
        "    def submit(self, request: ActionRequest) -> FirewallResponse:\n"
        "        session_id = request.session_id\n"
        "        with self._get_session_lock(session_id):\n"
        "            # 1. State Retrieval & Canonical Action Construction\n"
        "            state = self._get_state(session_id)\n"
        "            action = self._build_canonical_action(request, state)\n"
        "            self.audit_store.append(session_id, 'ACTION_RECEIVED', action.model_dump())\n"
        "            \n"
        "            # 2. Stateful Policy Evaluation (Three-Valued Logic)\n"
        "            policy_verdict, p_reasons = self.policy_engine.evaluate(action, state)\n"
        "            \n"
        "            # 3. Pure Decision Combination & Cascade Consultation\n"
        "            decision, route_trace = self._evaluate_and_combine(action, state, policy_verdict)\n"
        "            \n"
        "            # 4. Controlled Dispatch or Oversight Suspension\n"
        "            if decision == Decision.ALLOW:\n"
        "                token = self.token_store.issue_token(session_id, action.action_hash, state.head_hash)\n"
        "                exec_res = self.executor.execute(action, token)\n"
        "                self._apply_terminal_event(session_id, action, exec_res)\n"
        "                return FirewallResponse(action_id=action.action_id, status='EXECUTED', ...)\n"
        "            elif decision == Decision.REVIEW:\n"
        "                ticket = self.review_service.create_ticket(session_id, action, state.head_hash)\n"
        "                return FirewallResponse(action_id=action.action_id, status='PENDING_REVIEW', ticket_id=ticket.ticket_id)"
    )
    add_code_snippet(doc, code_snippet_core, "Listing 7.1: FirewallCore Request Interception and Dispatch Pipeline")

    # 7.5 Stateful Policy Engine and Three-Valued Logic
    add_h1(doc, "7.5", "Stateful Policy Engine and Three-Valued Logic")
    add_p(doc,
        "The `PolicyEngine` evaluates candidate actions against attribute rules utilizing three-valued logic: `PERMIT`, `PROHIBIT`, "
        "or `REVIEW`. Rules evaluate dynamic attributes including session data classification (`CONFIDENTIAL`, `RESTRICTED`), "
        "destination zones (`INTERNAL`, `EXTERNAL`), and tool categories (`EGRESS_EXTERNAL`, `PRIVILEGED_ADMIN`). If required evidence "
        "attributes are missing or tampered, the engine emits `EVIDENCE_MISSING`, triggering fail-closed oversight."
    )

    # 7.6 Advisory Monitor Interface and Rejection Cascade
    add_h1(doc, "7.6", "Advisory Monitor Interface and Rejection Cascade")
    add_p(doc,
        "Advisory monitors are integrated via `SafeMonitorWrapper`, which wraps all external monitor executions with: (1) strict "
        "per-call timeouts (default 200 ms); (2) exception catchers that map crashes to `MonitorVerdict.ERROR`; and (3) payload "
        "sanitization via `build_monitor_view()`. The tiered heuristic cascade (`CascadeAdapter`) inspects action patterns. Some actions "
        "may not require secondary model consultation; canonical evaluator latency is reported by arm and split in Chapter 8."
    )

    # 7.7 Decision Combinator Implementation
    add_h1(doc, "7.7", "Decision Combinator Implementation")
    add_p(doc,
        "The decision combinator `decide()` is implemented as a mathematically pure function in `src/firewall/decision/combinator.py`. "
        "Listing 7.2 displays the authoritative combinator implementation, verifying the strict enforcement of INV-03 and INV-04."
    )
    
    code_snippet_comb = (
        "def decide(config: DecisionConfig, policy_verdict: PolicyVerdict, evidence_status: EvidenceStatus,\n"
        "           monitor_verdict: MonitorVerdict, monitor_score: Optional[float] = None) -> Tuple[Decision, List[str]]:\n"
        "    # Invariant INV-03: Policy PROHIBIT is absolute\n"
        "    if policy_verdict == PolicyVerdict.PROHIBIT:\n"
        "        return Decision.DENY, ['POLICY_PROHIBIT: Absolute policy denial cannot be overridden']\n"
        "    \n"
        "    # Invariant INV-04: Fail-closed on missing evidence or monitor failure\n"
        "    if evidence_status in (EvidenceStatus.MISSING, EvidenceStatus.INVALID):\n"
        "        return Decision.REVIEW, [f'FAIL_CLOSED: Evidence status is {evidence_status.value}']\n"
        "    if monitor_verdict in (MonitorVerdict.ERROR, MonitorVerdict.TIMEOUT, MonitorVerdict.MALFORMED):\n"
        "        return Decision.REVIEW, [f'FAIL_CLOSED: Advisory monitor failure ({monitor_verdict.value})']\n"
        "    \n"
        "    # Advisory Escalation\n"
        "    if monitor_verdict == MonitorVerdict.MALICIOUS or (monitor_score and monitor_score >= config.review_threshold):\n"
        "        return Decision.REVIEW, ['ADVISORY_ESCALATION: Elevated risk detected by advisory monitor']\n"
        "    \n"
        "    return Decision.ALLOW, ['POLICY_PERMIT: Action authorized on fast path']"
    )
    add_code_snippet(doc, code_snippet_comb, "Listing 7.2: Pure Decision Combinator Delta Implementation")

    # 7.8 Human Oversight and Revalidation Service
    add_h1(doc, "7.8", "Human Oversight and Revalidation Service")
    add_p(doc,
        "The `ReviewService` manages human-in-the-loop oversight tickets. When a human reviewer resolves a ticket with `APPROVE`, "
        "`FirewallCore.resolve_review()` re-verifies that the session state hash has not changed since ticket creation (INV-05). "
        "If a concurrent action modified the state, the ticket is invalidated, preventing TOCTOU exploits."
    )

    # 7.9 Execution Token Store and Controlled Executor
    add_h1(doc, "7.9", "Execution Token Store and Controlled Executor")
    add_p(doc,
        "`TokenStore` in `src/firewall/executor/tokens.py` issues and redeems authorization tokens. Tokens are "
        "bound to the action and relevant state and are subject to expiry and single-use checks. HMAC-SHA256 is used separately by the "
        "evidence verifier. The store maintains a consumed-token set protected by a mutex; a consumed token cannot be reused."
    )
    
    # 7.10 Deterministic State Folding Engine
    add_h1(doc, "7.10", "Deterministic State Folding Engine")
    add_p(doc,
        "In `src/firewall/state/engine.py`, `apply_event(state: SessionState, event: StateEventEnvelope) -> SessionState` "
        "implements the monotonic fold operator Phi. It appends the event to the immutable history array, updates the data taint vector, "
        "and computes the new state head hash as: `head_hash = SHA256(prev_head_hash || seq || event_hash)`."
    )

    # 7.11 Tamper-Evident Hash-Chained Audit Store
    add_h1(doc, "7.11", "Tamper-Evident Hash-Chained Audit Store")
    add_p(doc,
        "`AuditStore` provides tamper-evident logging for all security events. Each record computes: "
        "`record_hash = SHA256(prev_hash || seq || event_type || payload_json)`. The method `verify_chain(session_id)` walks the chain "
        "from genesis to leaf; any bit-level modification or omitted event breaks the hash chain, triggering instant tamper alarms (INV-09)."
    )

    # 7.12 Implementation Traceability of Invariants INV-01 to INV-12
    add_h1(doc, "7.12", "Implementation Traceability of Invariants INV-01 to INV-12")
    add_p(doc,
        "Table 7.2 maps documented security invariants to implementation files and related repository tests. This mapping is not formal verification of each invariant."
    )
    
    headers_t72 = ["Invariant ID", "Invariant Name", "Authoritative Source File", "Verification Test Suite"]
    data_t72 = [
        ["INV-01", "Complete Interception", "src/firewall/core.py", "tests/integration/test_firewall_core.py::test_01"],
        ["INV-02", "Deterministic State Fold", "src/firewall/state/engine.py", "tests/invariants/test_security_invariants_state.py"],
        ["INV-03", "Policy Primacy", "src/firewall/decision/combinator.py", "tests/integration/test_firewall_core.py::test_02"],
        ["INV-04", "Fail-Closed Defaults", "src/firewall/decision/combinator.py", "tests/integration/test_firewall_core.py::test_03_07"],
        ["INV-05", "State Hash Revalidation", "src/firewall/oversight/service.py", "tests/integration/test_firewall_core.py::test_12_15"],
        ["INV-06", "Single-Use Tokens", "src/firewall/executor/tokens.py", "tests/integration/test_firewall_core.py::test_09_11"],
        ["INV-07", "Audit Continuity", "src/firewall/audit/store.py", "tests/invariants/test_security_invariants_state.py"],
        ["INV-08", "Action-Hash Binding", "src/firewall/executor/tokens.py", "tests/integration/test_firewall_core.py::test_14"],
        ["INV-09", "Audit Verifiability", "src/firewall/audit/store.py", "tests/integration/test_firewall_core.py::test_13"],
        ["INV-10", "Monitor Isolation", "src/firewall/state/views.py", "tests/unit/test_security_semantics_advisory.py"],
        ["INV-11", "Session Mutual Exclusion", "src/firewall/core.py", "tests/integration/test_firewall_core.py::test_08"],
        ["INV-12", "Monotonic Taint Tracking", "src/firewall/state/engine.py", "tests/invariants/test_security_invariants_state.py"],
    ]
    col_w_t72 = [1.1, 1.6, 1.8, 1.5]
    add_table(doc, headers_t72, data_t72, "Table 7.2", "Implementation Mapping of Mathematical Security Invariants in Code", col_w_t72)

    # 7.13 Technical Implementation Highlights and Code Snippets
    add_h1(doc, "7.13", "Technical Implementation Highlights and Code Snippets")
    add_p(doc,
        "The AASF implementation sanitizes monitor views to redact credential-like values. Tests exercise redaction in monitor and reviewer views. "
        "Sanitization is implemented in `src/firewall/state/views.py`; this description does not establish that every possible secret format is detected."
    )

    add_page_break(doc)

# AASF Implementation Traceability Matrix

This document provides complete, line-level and module-level mapping between the academic claims, architectural specifications, and empirical findings presented in the **AASF B.Tech Project Report** and their authoritative implementation in the source repository.

---

## 1. Core Architecture and Subsystem Traceability

| Report Subsystem | Functional Scope | Source Implementation File | Key Classes / Functions | Primary Test Verification |
|---|---|---|---|---|
| **Firewall Orchestrator** | Interception, session locking, vertical slice coordination | `src/firewall/core.py` | `FirewallCore.submit()`, `resolve_review()`, `RouteTrace` | `tests/integration/test_firewall_core.py` |
| **Deterministic State Fold ($\Phi$)** | Monotonic history accumulation, state hashing, taint tracking | `src/firewall/state/engine.py` | `apply_event()`, `initial_state()`, `compute_state_hash()` | `tests/invariants/test_security_invariants_state.py` |
| **Stateful Policy Engine** | Three-valued ABAC evaluation, evidence verification | `src/firewall/policy/evaluator.py` | `PolicyEngine.evaluate()`, `create_default_stateful_policy()` | `tests/unit/test_policy.py` |
| **Pure Decision Combinator ($\Delta$)** | Pure invariant synthesis, fail-closed defaults | `src/firewall/decision/combinator.py` | `decide()`, `DecisionConfig`, `Decision` | `tests/unit/test_decision.py` |
| **Advisory Cascades** | Fast-path heuristic routing, model client timeouts | `src/firewall/cascade/adapter.py` | `CascadeAdapter`, `SafeMonitorWrapper` | `tests/unit/test_monitors.py` |
| **Human Oversight Platform** | Review ticketing, state revalidation (INV-05) | `src/firewall/oversight/service.py` | `ReviewService.create_ticket()`, `resolve_ticket()` | `tests/unit/test_oversight.py` |
| **Execution Token Store** | Single-use HMAC-SHA256 tokens, replay prevention | `src/firewall/executor/tokens.py` | `TokenStore.issue_token()`, `consume_token()` | `tests/unit/test_executor.py` |
| **Controlled Tool Executor** | Authorized tool invocation dispatch | `src/firewall/executor/executor.py` | `ControlledExecutor.execute()` | `tests/integration/test_firewall_core.py` |
| **Cryptographic Audit Store** | SHA-256 hash chaining, tamper detection | `src/firewall/audit/store.py` | `AuditStore.append()`, `verify_chain()` | `tests/unit/test_audit.py` |
| **Information Isolation Barrier** | Sensitive credential redaction (INV-10) | `src/firewall/state/views.py` | `build_monitor_view()`, `build_reviewer_view()` | `tests/unit/test_security_semantics_advisory.py` |

---

## 2. Security Invariants (INV-01 to INV-12) Verification Trace

| Invariant | Formal Statement | Implementation Location | Test Assertion Location |
|---|---|---|---|
| **INV-01** | $\forall a \in \text{Actions}: \text{Executed}(a) \implies \text{Intercepted}(a)$ | `src/firewall/core.py:340` | `tests/integration/test_firewall_core.py::test_01` |
| **INV-02** | $S_n = \Phi(S_{n-1}, a_n, r_n)$ is unique and deterministic | `src/firewall/state/engine.py:48` | `tests/invariants/test_security_invariants_state.py` |
| **INV-03** | $P = \text{PROHIBIT} \implies \text{Decision} = \text{DENY}$ | `src/firewall/decision/combinator.py:85` | `tests/integration/test_firewall_core.py::test_02` |
| **INV-04** | $E \in \{\text{MISSING}, \text{INVALID}\} \implies \text{Decision} \neq \text{ALLOW}$ | `src/firewall/decision/combinator.py:92` | `tests/integration/test_firewall_core.py::test_03_07` |
| **INV-05** | $\text{ResolveReview}(\text{tkt}, \text{APPROVE}) \implies S_{\text{now}} = \text{tkt.state\_hash}$ | `src/firewall/core.py:680` | `tests/integration/test_firewall_core.py::test_12_15` |
| **INV-06** | $\text{Redeem}(T) \implies \text{Valid}(T) \land \neg \text{Consumed}(T)$ | `src/firewall/executor/tokens.py:75` | `tests/integration/test_firewall_core.py::test_09_11` |
| **INV-07** | $\forall i: \text{rec}_i.\text{prev\_hash} = \text{SHA256}(\text{rec}_{i-1})$ | `src/firewall/audit/store.py:65` | `tests/invariants/test_security_invariants_state.py` |
| **INV-08** | $\text{TokenAuth}(T, a) \implies T.\text{action\_hash} = \text{SHA256}(a)$ | `src/firewall/executor/tokens.py:88` | `tests/integration/test_firewall_core.py::test_14` |
| **INV-09** | $\text{VerifyChain}(S) = \text{True} \iff \text{Chain Untampered}$ | `src/firewall/audit/store.py:110` | `tests/integration/test_firewall_core.py::test_13` |
| **INV-10** | $\forall m \in \text{Monitors}: \text{Input}(m) = \text{MonitorView}$ (Redacted) | `src/firewall/state/views.py:120` | `tests/unit/test_security_semantics_advisory.py` |
| **INV-11** | $\forall s \in \text{Sessions}: \text{ConcurrentAccess}(s) \text{ guarded by } L_s$ | `src/firewall/core.py:320` | `tests/integration/test_firewall_core.py::test_08` |
| **INV-12** | $\text{Taint}(S_n) \ge \text{Taint}(S_{n-1})$ (Monotonically non-decreasing) | `src/firewall/state/engine.py:95` | `tests/invariants/test_security_invariants_state.py` |

---

## 3. Empirical Data and Pre-Registered Benchmark Traceability

All numbers cited in Chapter 8 correspond directly to reproducible evaluation files:

- **DEV Split (N=32):** `docs/research/shrishti/results/dev_split_results.json`
- **CAL Split (N=8):** `docs/research/shrishti/results/cal_split_results.json`
- **TEST-IN Split (N=8):** `docs/research/shrishti/results/test_in_results.json`
- **TEST-NOVEL Split (N=4):** `docs/research/shrishti/results/test_novel_results.json`
- **Pre-Registration Commitment:** `docs/prereg/PREREG-001.md` (Digest: `88038e76161686bd3cc4fd0a12757e9d4264f406a7d5399a9ba6bff92ee37fd5`)
- **Sealed Test Commitment:** `docs/prereg/TEST_COMMITMENT.sha256`


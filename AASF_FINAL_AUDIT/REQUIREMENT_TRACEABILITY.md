# AASF COMPLETE REQUIREMENT TRACEABILITY MATRIX
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Requirements & Compliance Engineering Team  
**Date:** November 02, 2026  
**Status:** Canonical End-to-End Traceability  

---

## 1. Traceability Table

| Requirement ID | Requirement Description | Document Reference | Target Component | Source Code Implementation | Verification Test | Status |
|---|---|---|---|---|---|:---:|
| **FR-GW-01** | Synchronous In-Process Mediation | `04_PRD.md` §3.1 | Gateway ($C_1$) | `src/firewall/core.py` (`FirewallCore.submit`) | `tests/integration/test_firewall_core.py` | **FULL** |
| **FR-GW-02** | Canonical Action Serialization & Hashing | `04_PRD.md` §3.1 | Contracts | `src/firewall/contracts/hashing.py` (`compute_action_hash`) | `tests/unit/test_hashing.py` | **FULL** |
| **FR-GW-03** | Monotonic Action Sequence Assignment | `04_PRD.md` §3.1 | Gateway ($C_1$) | `src/firewall/core.py` (`_action_seqs`) | `tests/integration/test_firewall_core.py` | **FULL** |
| **FR-GW-04** | Per-Session Single In-Flight Concurrency | `04_PRD.md` §3.1 | Gateway ($C_1$) | `src/firewall/core.py` (`_session_locks`) | `tests/integration/test_firewall_core.py` | **FULL** |
| **FR-GW-05** | Pending Review Session Lockout (BUSY) | `04_PRD.md` §3.1 | Gateway ($C_1$) | `src/firewall/core.py` (`has_pending_review`) | `tests/integration/test_firewall_core.py` | **FULL** |
| **FR-POL-01** | Deterministic Three-Valued Logic Evaluation| `04_PRD.md` §3.2 | Policy ($C_3$) | `src/firewall/policy/evaluator.py` (`PolicyEngine`) | `tests/unit/test_policy.py` | **FULL** |
| **FR-POL-02** | Rule-Order Independence & Prohibit Supremacy| `04_PRD.md` §3.2 | Policy ($C_3$) | `src/firewall/policy/evaluator.py` (`evaluate`) | `tests/unit/test_policy.py` | **FULL** |
| **FR-POL-03** | Missing-Evidence Escalation | `04_PRD.md` §3.2 | Policy ($C_3$) | `src/firewall/policy/evaluator.py` (Rule `MAYBE`) | `tests/unit/test_policy.py` | **FULL** |
| **FR-POL-04** | Canonical Stateful Benchmark Rules R1–R5 | `04_PRD.md` §3.2 | Policy ($C_3$) | `src/firewall/policy/rules.py` (`create_default_stateful_policy`)| `tests/unit/test_policy.py` | **FULL** |
| **FR-STA-01** | Pure Functional State Fold $\Phi(H_t, \text{Reg})$ | `04_PRD.md` §3.3 | State ($C_2$) | `src/firewall/state/engine.py` (`apply_event`) | `tests/unit/test_state_engine.py` | **FULL** |
| **FR-STA-02** | Cryptographic SHA-256 State-Head Chaining | `04_PRD.md` §3.3 | State ($C_2$) | `src/firewall/state/engine.py` (`compute_state_head`) | `tests/unit/test_state_engine.py` | **FULL** |
| **FR-STA-03** | HMAC-SHA256 Tool Evidence Receipt Verifier | `04_PRD.md` §3.3 | State ($C_2$) | `src/firewall/state/evidence.py` (`HmacEvidenceVerifier`) | `tests/unit/test_state_engine.py` | **FULL** |
| **FR-STA-04** | Cumulative Zone Egress Counting | `04_PRD.md` §3.3 | State ($C_2$) | `src/firewall/state/engine.py` (`EgressCounter`) | `tests/unit/test_state_engine.py` | **FULL** |
| **FR-STA-05** | Implicit & Explicit Resource Binding Modes | `04_PRD.md` §3.3 | State ($C_2$) | `src/firewall/state/engine.py` (`BindingMode`) | `tests/unit/test_state_engine.py` | **FULL** |
| **FR-STA-06** | Allow-Listed Information Projections | `04_PRD.md` §3.3 | State ($C_2$) | `src/firewall/state/views.py` (`build_monitor_view`) | `tests/invariants/test_security_invariants_state.py`| **FULL** |
| **FR-MON-01** | Action-Only Risk Monitor (Arm B4) | `04_PRD.md` §3.4 | Monitor ($C_4$) | `src/firewall/monitor/action_only.py` | `tests/unit/test_monitors.py` | **FULL** |
| **FR-MON-02** | Transcript-Based Risk Monitor (Arm B5) | `04_PRD.md` §3.4 | Monitor ($C_4$) | `src/firewall/monitor/transcript.py` | `tests/unit/test_monitors.py` | **FULL** |
| **FR-MON-03** | Hybrid State-Aware Risk Monitor (Arm P1) | `04_PRD.md` §3.4 | Monitor ($C_4$) | `src/firewall/monitor/hybrid.py` | `tests/unit/test_monitors.py` | **FULL** |
| **FR-MON-04** | Safe Fault-Isolation Wrapper (Fail-Closed)| `04_PRD.md` §3.4 | Monitor ($C_4$) | `src/firewall/monitor/base.py` (`SafeMonitorWrapper`) | `tests/unit/test_monitors.py` | **FULL** |
| **FR-MON-05** | Strict Canonical JSON Output Parsing (D-26) | `04_PRD.md` §3.4 | Monitor ($C_4$) | `src/firewall/monitor/model_client.py` (`parse_monitor_output`) | `tests/unit/test_monitors.py` | **FULL** |
| **FR-DEC-01** | Pure Decision Combinator $\Delta$ (D1–D5e) | `04_PRD.md` §3.5 | Decision ($C_5$) | `src/firewall/decision/combinator.py` (`decide`) | `tests/unit/test_decision.py` | **FULL** |
| **FR-DEC-02** | Mandatory Review Tool Classes Enforcement | `04_PRD.md` §3.5 | Decision ($C_5$) | `src/firewall/decision/combinator.py` (Rule D5c) | `tests/unit/test_decision.py` | **FULL** |
| **FR-EXE-01** | Single-Use Authorization Token Gating | `04_PRD.md` §3.6 | Executor ($C_6$) | `src/firewall/executor/tokens.py` (`TokenStore`) | `tests/unit/test_executor.py` | **FULL** |
| **FR-EXE-02** | Token State-Head & Hash Binding Recheck | `04_PRD.md` §3.6 | Executor ($C_6$) | `src/firewall/executor/tokens.py` (`consume_token`) | `tests/unit/test_executor.py` | **FULL** |
| **FR-EXE-03** | Controlled Tool Execution Dispatch | `04_PRD.md` §3.6 | Executor ($C_6$) | `src/firewall/executor/executor.py` (`ControlledExecutor`) | `tests/unit/test_executor.py` | **FULL** |
| **FR-REV-01** | Review Ticket Creation & Expiry Lifecycle | `04_PRD.md` §3.7 | Oversight ($C_8$)| `src/firewall/oversight/service.py` (`ReviewService`) | `tests/unit/test_oversight.py` | **FULL** |
| **FR-REV-02** | Review Approval Revalidation Check | `04_PRD.md` §3.7 | Gateway ($C_1$) | `src/firewall/core.py` (`resolve_review`) | Code inspection | **PARTIAL (SEC-01)** |
| **FR-AUD-01** | Append-Only SHA-256 Audit Store | `04_PRD.md` §3.8 | Audit ($C_7$) | `src/firewall/audit/store.py` (`AuditStore`) | `tests/unit/test_audit.py` | **PARTIAL (In-Memory)** |
| **FR-REG-01** | Authoritative Tool, Resource & Zone Registry | `04_PRD.md` §3.9 | Registry ($C_9$) | `src/firewall/state/registry.py` (`Registry`) | `tests/unit/test_registry.py` | **FULL** |
| **FR-CFG-01** | YAML Configuration Loading | `04_PRD.md` §3.10| Config | `config/*.yaml` | File inspection | **NOT IMPLEMENTED** |
| **FR-EXP-01** | Reproducible Experiment Runner | `04_PRD.md` §3.11| Harness ($C_{11}$)| `experiments/run_experiment.py` (0 bytes) | File inspection | **NOT IMPLEMENTED** |
| **FR-DASH-01**| Metrics & Review UI Dashboard | `04_PRD.md` §3.12| Dashboard | None (Deferred to Phase 9 per D-06, D-28) | Documented | **DEFERRED** |

---
*End of Requirement Traceability Matrix.*


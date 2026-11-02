# AASF Phase 1 Audit: Architecture and Diagram Traceability Audit

**Audit Phase:** Phase F - System Architecture & Diagram Verification  
**Date:** 2026-11-02  
**Target Repository:** `sksnehal/ai-agent-permission-firewall`  
**Audit Target Commit:** `943559a466356d3536898f58ac9c594b03d4f418`  
**Diagram Directory:** `AASF_FINAL_PROJECT_REPORT/diagrams/` (13 PNG assets)  
**Overall Architectural Traceability Verdict:** **PARTIALLY TRACEABLE WITH IDENTIFIED STRUCTURAL & VISUAL DISCREPANCIES**

---

## 1. Executive Summary

This audit performs an element-by-element verification of all architectural figures, data flow diagrams (DFDs), UML diagrams, and lifecycle charts incorporated in the final B.Tech project report against the canonical Python implementation in `src/firewall/`.

The evaluation assesses:
1. **Component Name & Structure Alignment:** Do diagrammed components, classes, and methods correspond to physical source code?
2. **Behavioral & Interaction Fidelity:** Do sequence and activity flows reflect actual execution paths?
3. **Data Boundary & Isolation Integrity:** Are isolation barriers, token lifetimes, and state folds accurately modeled?
4. **Visual & Typographical Quality:** Are diagram assets legible, free from rendering collisions, and professionally formatted?

### Key Findings Summary:
- **Conceptual High-Fidelity:** The overall system architecture (Fig 6.1), DFD Level 1 (Fig 6.10), token lifecycle (Fig 6.9), MonitorView isolation (Fig 6.8), and activity flow (Fig 6.11) accurately reflect AASF's multi-tiered design and fail-closed security guarantees.
- **OO vs. Functional Implementation Mismatch (Fig 6.7):** The UML Class Diagram presents an idealized object-oriented design (`DecisionCombinator` class, `TokenManager` class, `StateEngine` class with `apply_action`), whereas the production codebase implements functional, immutable architectures (`decide()` pure function, `TokenStore` with atomic hash checks, `apply_event()` pure state fold).
- **Invariant ID Labeling Conflict (Fig 6.4):** Figure 6.4 mislabels invariant IDs (referencing INV-01 as Monotonicity and INV-11 as Rollback Protection), contradicting the pre-registered and report-internal threat model (`docs/01_THREAT_MODEL.md` §8) where INV-01 is Complete Mediation, INV-11 is Concurrency Locks, and INV-12 is Monotonicity.
- **Rendering Collisions & Visual Defects (Fig 6.3 & Fig 6.6):** Figure 6.3 suffered catastrophic text-layer collisions during rendering, producing garbled overlapping labels across 8 decision nodes. Figure 6.6 exhibits minor label overlapping.
- **Orphaned Asset (Fig 6.2):** `fig6_2_agent_execution_pipeline.png` exists in the diagram asset directory but was omitted from the generated document in favor of `fig6_10_dfd_level_1.png`.

---

## 2. Comprehensive Diagram Audit Matrix

| Diagram Asset | Report Figure Ref | Declared Title | Canonical Source File(s) | Traceability Status | Primary Defects / Discrepancies |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `fig4_1_project_gantt_chart.png` | Figure 4.1 | Project Implementation Roadmap & Gantt Chart | `docs/08_IMPLEMENTATION_ROADMAP.md` | **VERIFIED** | None. Accurate 17-week phase breakdown. |
| `fig5_1_system_use_case_diagram.png` | Figure 5.1 | System Use Case Diagram Across Actors | `docs/01_THREAT_MODEL.md` §3 | **VERIFIED** | None. Accurately maps Agent, Reviewer, and Tool actors. |
| `fig6_6_dfd_level_0.png` | Figure 5.2 | Context-Level Data Flow Diagram (DFD Level 0) | `src/firewall/core.py` | **MINOR DEFECT** | Text collision between "Review Ticket / HMAC" and "Approve / Reject". |
| `fig6_1_overall_aasf_architecture.png` | Figure 6.1 | Overall Multi-Tiered AASF Architecture | `src/firewall/core.py`, `src/firewall/` | **VERIFIED** | Accurate high-level architectural layering. |
| `fig6_10_dfd_level_1.png` | Figure 6.2 | Data Flow Diagram Level 1 (Subsystems) | `src/firewall/core.py:submit()` | **VERIFIED** | Clean 6-subsystem data flow decomposition. |
| `fig6_7_uml_class_diagram.png` | Figure 6.3 | UML Class Diagram of Firewall Core | `src/firewall/contracts/`, `policy/`, `decision/` | **DISCREPANCY** | Class names & method signatures deviate from code (`TokenManager` vs `TokenStore`, class `DecisionCombinator` vs pure function `decide()`). |
| `fig6_5_uml_sequence_diagram.png` | Figure 6.4 | UML Sequence Diagram: Action Authorization | `src/firewall/core.py:submit()` | **MINOR DISCREPANCY** | Depicts agent directly calling Executor; in-process AASF executes internally on `ALLOW`. |
| `fig6_11_uml_activity_diagram.png` | Figure 6.5 | UML Activity Diagram: Cascading & Fallback | `src/firewall/decision/combinator.py` | **VERIFIED** | Accurately models three-branch evaluation and fallback. |
| `fig6_4_hash_chained_state_architecture.png` | Figure 6.6 | Monotonic State Fold & Hash Chaining | `src/firewall/state/engine.py` | **DISCREPANCY** | Bottom text misidentifies invariant numbers (INV-01 as Monotonicity, INV-11 as Rollback). |
| `fig6_8_monitorview_isolation.png` | Figure 6.7 | MonitorView Information Isolation Barrier | `src/firewall/state/views.py` | **VERIFIED** | 100% faithful to regex credential scrubbing and oracle stripping. |
| `fig6_9_token_lifecycle.png` | Figure 6.8 | Single-Use Authorization Token Lifecycle | `src/firewall/executor/tokens.py` | **VERIFIED** | Accurate lifecycle: `MINTED` $\to$ `VALIDATED` $\to$ `CONSUMED` / `EXPIRED`. |
| `fig6_3_decision_combinator_flowchart.png` | Figure 6.9 | Decision Combinator Flowchart | `src/firewall/decision/combinator.py` | **SEVERE DEFECT** | Severe text collisions on 8 boxes render nodes illegible. |
| `fig6_2_agent_execution_pipeline.png` | *Orphaned* | End-to-End Agent Execution Pipeline | `src/firewall/core.py` | **UNUSED** | Asset present in folder but not linked in Word dissertation. |

---

## 3. Deep-Dive Component Traceability Analysis

### 3.1 Class & Structural Mapping: Figure 6.7 vs. Source Code

The UML Class Diagram in Figure 6.7 introduces several naming and paradigm abstractions that differ from the implemented Python codebase:

```
+-------------------------------------------------------------------------------+
|                      FIGURE 6.7 CLASS vs CODE IMPLEMENTATION                   |
+--------------------------+----------------------------------------------------+
| Diagram Representation   | Actual Source Implementation                       |
+--------------------------+----------------------------------------------------+
| class StateEngine        | Module `src/firewall/state/engine.py`              |
|  - apply_action(action)  |  - Function: `apply_event(state, action, result)`   |
|  - get_state(session_id) |  - State stored in `FirewallCore._session_states`  |
|  - verify_rollback(head) |  - State hash checked via `compute_state_hash()`   |
+--------------------------+----------------------------------------------------+
| class DecisionCombinator | Module `src/firewall/decision/combinator.py`       |
|  - combine(v_pol, v_mon) |  - Pure function: `decide(valid, policy, monitor)` |
|  - check_prohibit_...()  |  - Hardcoded combinator dominance logic            |
+--------------------------+----------------------------------------------------+
| class TokenManager       | Class `TokenStore` in `src/firewall/executor/`     |
|  - mint_token(...)       |  - Method: `issue_token(...)`                      |
|  - validate_token(...)   |  - Method: `consume_token(...)` (atomic check)     |
|  - revoke_token(...)     |  - Handled via expiration TTL / single-use flag    |
+--------------------------+----------------------------------------------------+
| class HybridMonitor (P1) | Class `CascadeAdapter` & `SafeMonitorWrapper`      |
|  - assess(view)          |  - Wrapped in `src/firewall/cascade/adapter.py`    |
+--------------------------+----------------------------------------------------+
| ControlledExecutor       | Class `ControlledExecutor` in `executor.py`        |
|  - Missing from Fig 6.7  |  - Authoritative tool dispatcher                   |
+--------------------------+----------------------------------------------------+
```

**Architectural Assessment:**
While Figure 6.7 correctly communicates the functional boundaries of each subsystem, it models them as classical Object-Oriented stateful classes. The production code is architecturally cleaner and more defensible: `decide` is a pure referentially transparent mathematical function, and state transitions are pure state-machine folds (`apply_event`). The final defense should clarify that Figure 6.7 depicts a high-level conceptual component model rather than a 1:1 AST class dump.

---

### 3.2 Invariant Traceability Conflict: Figure 6.4

In Figure 6.4 ("Monotonic State Transition Fold (Phi) and Cryptographic Hash Chaining"), the explanatory callout at the base of the diagram asserts:
- `"INV-01 (Monotonicity): State progression is strictly append-only; past transitions cannot be altered."`
- `"INV-07 (Preimage Resistance): State hash commits to canonical JSON representation (RFC 8785)."`
- `"INV-11 (Rollback Protection): Out-of-order execution or replayed state tokens are rejected with STALE_STATE."`

**Contradiction with Threat Model & Report Text:**
In `docs/01_THREAT_MODEL.md` §8 and the report's own Chapter 3 & Chapter 6 text:
- **INV-01** is formally defined as **Complete Mediation**: $\forall a \in \text{Actions}: \text{Executed}(a) \implies \text{Intercepted}(a)$.
- **INV-02** is **State Transition Determinism & History Binding**: $S_n = \Phi(S_{n-1}, a_n, r_n)$.
- **INV-07** is **Audit Preimage Resistance**: $\forall i: \text{rec}_i.\text{prev\_hash} = \text{SHA256}(\text{rec}_{i-1})$.
- **INV-11** is **Thread-Safe Concurrency & Session Locks**: $\forall s: \text{Lock}(s)$.
- **INV-12** is **Monotonic State Accumulation**: $\text{Taint}(S_n) \ge \text{Taint}(S_{n-1})$.

**Verdict:** The diagram generator script mistakenly assigned arbitrary invariant numbers to properties in the callout. While the underlying properties (monotonicity, preimage resistance, and rollback rejection) are implemented and verified in code, the numbered citations in Figure 6.4 contradict the formal invariant definitions.

---

### 3.3 Visual & Rendering Defect Analysis: Figure 6.3 & Figure 6.6

#### Figure 6.3: Decision Combinator Flowchart
- **Visual Failure:** Severe text overlay collision.
- **Root Cause:** In the plotting script that generated `fig6_3_decision_combinator_flowchart.png`, the title strings and body text strings were blitted at identical coordinate offsets `(x, y)` without vertical line spacing or bounding box padding.
- **Affected Nodes:**
  1. Box 1: `"Incoming Request"` overlaps `"Action Request"`.
  2. Box 2: `"Policy Evaluation"` overlaps `"PolicyEngine.eval(req, S_t)"` and `V_pol == PERMIT`.
  3. Box 3: `"PROHIBIT Dominance"` overlaps `"DENY"`, producing `"PROHIEDNYminance"`.
  4. Box 4: `"Check Oversight Need?"` overlaps `"Is Advisory Monitor = SUSPICIOUS?"`.
  5. Box 5: `"EVIDENCE_MISSING"` overlaps `"REVIEW"`, producing `"EVIDEREVIEWISSING"`.
  6. Box 6: `"Mint Authorization Token"` overlaps `"Decision ALLOW"`.
  7. Box 7: `"Generate Review Ticket"` overlaps `"Decision REVIEW"`.
  8. Box 8: `"status: EXECUTED | DENIED | PENDING"` overlaps `"FirewallResponse"`.
- **Impact on Submission:** While conceptually sound, this figure appears defective upon academic or industrial review and must be re-rendered cleanly before external presentation.

#### Figure 6.6: Context-Level DFD Level 0
- **Visual Failure:** Minor label collision on the vertical data flow connecting process `0.0 AASF Security Gateway` to external entity `Human Reviewer`.
- **Text Observed:** `"Review Ticket / HMAC"` is printed directly over `"Approve / Reject"`.
- **Impact:** Legibility is compromised on the reviewer return arrow.

---

### 3.4 Operational Flow Traceability: Figure 6.5 (Sequence Diagram)

Figure 6.5 outlines the action authorization lifecycle across seven chronological steps:
1. `submit(ActionRequest)` $\to$ `FirewallCore`
2. `get_state()` $\to$ `StateEngine`
3. `evaluate(action, S_t)` $\to$ `PolicyEngine`
4. `assess(view)` $\to$ `Monitor`
5. `Response(ALLOW, Token)` $\to$ `Agent`
6. `execute_tool(Token)` $\to$ `Executor`
7. `transition_state(action)` $\to$ `StateEngine`

**Architectural Comparison:**
- In the **in-process AASF deployment** (`FirewallCore.submit()`), Step 5 and Step 6 do not return a raw execution token to the unprivileged agent process. If a request is granted `ALLOW`, `FirewallCore` immediately passes the internally generated token to `ControlledExecutor.execute()`, executing the tool within the trusted kernel boundary, and returns the resulting value envelope to the agent.
- **Auditor Note:** Step 5/6 as drawn in Figure 6.5 represents an **out-of-process / client-proxy deployment model** (e.g., sidecar proxy pattern) where the client receives a bearer token to present to a distinct executor service. This distinction between in-process controlled execution and out-of-process proxying should be explicitly noted in the report commentary.

---

## 4. Remediation Recommendations for Final Presentation & Defense

1. **Re-render Figure 6.3:** Re-run diagram generation with proper vertical coordinate spacing (`y_offset + 0.15`) to eliminate the overlapping text layers.
2. **Re-render Figure 6.6:** Separate the forward flow label `"Review Ticket / Context"` from the backward flow label `"Approval / Rejection Verdict"`.
3. **Synchronize Invariant IDs in Figure 6.4:** Correct the callout text in Figure 6.4 to reference **INV-12** for Monotonicity, **INV-02** for History Determinism, and **INV-07** for Cryptographic Audit Preimage Resistance.
4. **Clarify Figure 6.7 in Defense Slides:** Note that Figure 6.7 illustrates the high-level subsystem role abstraction, while the actual implementation embraces functional pure deciders (`decide()`) and state transforms (`apply_event()`).

---

## 5. Phase F Conclusion

The overall architectural design depicted across the 13 report figures is fundamentally aligned with the implemented system. The core security guarantees—in-process mediation, three-valued lattice evaluation, single-use token lifecycle, and cryptographic audit chaining—are completely supported by the underlying Python engine. Identified defects are confined to typographical/visual layout rendering and diagrammatic labeling inconsistencies.


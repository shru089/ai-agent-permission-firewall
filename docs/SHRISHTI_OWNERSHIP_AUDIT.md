# Shrishti's Ownership Audit: AI/ML, Runtime Risk & Threat Detection

**Date:** 2026-10-29  
**Repository:** `ai-agent-permission-firewall` / Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Antigravity (AI Assistant Pair Programmer)  
**Subject:** Comprehensive ownership audit of contributions attributable to **Shrishti** (`shru089 <shrishtis089@gmail.com>`).  
**Status:** Audit Complete. No runtime code modified.

---

## 1. Executive Verdict

### Verdict: **Partially Aligned with Significant Scope Drift and Critical Missing Core Deliverables**

#### Evidence Summary:
1. **Strong Foundational Work in State Tracking ($C_2$):** Shrishti has successfully authored and validated the deterministic state engine ([`src/firewall/state/engine.py`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/state/engine.py)), provenance tagging, and allow-listed view projections ([`src/firewall/state/views.py`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/state/views.py)), establishing the information barriers (`INV-07`, `INV-08`, `INV-12`) essential for multi-step contextual threat detection.
2. **Early Exploratory Pilot Preserved:** Shrishti authored the initial rejection-cascade exploration (branch `shru089/integrate-rejection-cascade`, PR #1), importing 21 analysis/testing scripts in [`experiments/scripts/`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/scripts) and 3 CSV datasets in [`experiments/results/`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/results).
3. **Severe Scope Drift into Teammates' Domains:** In recent commits (notably `67404fd`), Shrishti's account committed implementations for:
   - **Policy Engine ($C_3$):** [`src/firewall/policy/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/policy) $\to$ Owned by **Karishma**.
   - **Gateway & Controlled Executor ($C_1, C_6$):** [`src/firewall/core.py`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/core.py), [`src/firewall/executor/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/executor) $\to$ Owned by **Akshat**.
   - **Human Oversight & Audit Store ($C_7, C_8$):** [`src/firewall/oversight/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/oversight), [`src/firewall/audit/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/audit) $\to$ Owned by **Snehal**.
   - **Decision Combinator ($C_5$):** [`src/firewall/decision/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/decision) $\to$ Co-owned by **Karishma and Akshat**.
4. **Critical Deliverables Missing in Her Own Primary Domain:** While implementing teammates' runtime modules, Shrishti's primary research deliverables remain unbuilt:
   - **Context-Aware Monitors ($C_4$):** Baseline monitors $B_4$ (`ActionOnlyMonitor`), $B_5$ (`TranscriptMonitor`), and proposed arm $P_1$ (`HybridMonitor`) do not exist in [`src/firewall/monitor/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/monitor) (only generic mock interfaces exist).
   - **Experiment Runner & Evaluation Harness ($C_{11}$):** [`experiments/evaluate.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/evaluate.py), [`experiments/metrics.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/metrics.py), [`experiments/run_experiment.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/run_experiment.py), and [`experiments/stats.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/stats.py) are **completely empty (0 bytes)**.
   - **Benchmark Datasets:** [`experiments/datasets/dev/`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/datasets/dev) and `cal/` contain zero scenario specifications.
   - **Statistical Power Analysis (`OQ-11`):** Minimum template/sample size calculations remain unperformed.

**Verdict Conclusion:** Shrishti has built a functioning infrastructure for the overall team, but her own core research question (**"Baseline Risk Detection vs Proposed Risk Detection"**) cannot be evaluated until she shifts focus back to her primary deliverables.

---

## 2. Agreed Research Scope and Team Boundaries

### Shrishti's Assigned Research Role
- **Primary Topic:** Baseline Risk Detection vs. Proposed Risk Detection.
- **Broader Role:** AI/ML + AI Security (owning AI Risk & Threat Detection).
- **Core Research Questions:**
  - **RQ-0 (Motivating):** Can contextual information improve multi-step threat detection in AI agent workflows while maintaining acceptable performance and overhead?
  - **RQ-1 (Operational):** How do action-only ($B_4$), transcript-based ($B_5$), deterministic stateful ($B_6$), and hybrid/cascade-based ($P_1$) permission monitors compare in terms of malicious-action prevention, benign-task completion, human-review burden, and decision latency?

### Formal Team Ownership Matrix (per `CODEOWNERS` and `docs/rules.md §2`)

| Component / Subsystem | Primary Owner | Reviewer / Integration Partner | Shrishti's Role |
| :--- | :--- | :--- | :--- |
| **Contracts & Schemas** (`src/firewall/contracts/`) | All 4 Members | Cross-team review | Co-owner (state & monitor models) |
| **State Engine & Views ($C_2$)** (`src/firewall/state/`) | **Shrishti** | Karishma (schema co-owner) | **Primary Owner** |
| **Runtime Risk Monitors ($C_4$)** (`src/firewall/monitor/`) | **Shrishti** | Karishma (decision integration) | **Primary Owner** |
| **Experiment Runner & Metrics ($C_{11}$)** (`experiments/`) | **Shrishti** | Snehal (metric audit), Akshat (specs) | **Primary Owner** |
| **Policy Engine ($C_3$, `config/policy_*`)** | **Karishma** | Shrishti (Hypothesis tests) | Reviewer / Consumer |
| **Registry ($C_9$, `config/registry.yaml`)** | **Karishma** | Shrishti (state lookups) | Consumer |
| **Gateway & Interceptor ($C_1$)** (`src/firewall/core.py`) | **Akshat** | Shrishti (monitor view injection) | Consumer |
| **Controlled Executor ($C_6$)** (`src/firewall/executor/`) | **Akshat** | Snehal (audit logging) | Consumer |
| **Simulated Tools ($C_{10}$)** (`src/firewall/tools/sim/`) | **Akshat** | Shrishti (scenario runner) | Consumer |
| **Decision Function ($C_5$)** (`src/firewall/decision/`) | **Karishma & Akshat** | Shrishti | Reviewer |
| **Human Oversight ($C_8$)** (`src/firewall/oversight/`) | **Snehal** | Shrishti (review simulation $M\text{-REVR}$) | Consumer |
| **Audit Store ($C_7$)** (`src/firewall/audit/`) | **Snehal** | Shrishti (evaluation JSONL export) | Consumer / Exporter |
| **Test Sets (`experiments/datasets/test/`, `labels/`)** | **Akshat & Snehal** | Independent label audits | **Strictly Excluded from Authoring** (`INV-08`) |

---

## 3. Traceable Contribution Inventory

The inventory classifies all relevant repository assets into six formal categories:
- **`[OWNED]`**: Directly within Shrishti's assigned risk-detection and state research.
- **`[SHARED INTEGRATION]`**: Jointly owned interfaces necessary to connect or evaluate components.
- **`[CROSS-TEAM SUPPORT]`**: Work performed to assist another member's component.
- **`[OUTSIDE PRIMARY SCOPE]`**: Primarily belonging to another member.
- **`[UNASSIGNED / UNCLEAR]`**: Ownership cannot be established from records.
- **`[MISSING DELIVERABLE]`**: Required in Shrishti's area but unbuilt or incomplete.

```
+========================================================================================================================+
|                                    SHRISHTI'S CONTRIBUTION CLASSIFICATION MATRIX                                      |
+=============================================+===========================+=====================+========================+
| Artifact / Path                             | Classification            | Current Status      | Primary Responsibility |
+=============================================+===========================+=====================+========================+
| src/firewall/state/engine.py                | OWNED                     | Implemented, Tested | Shrishti               |
| src/firewall/state/views.py                 | OWNED                     | Implemented, Tested | Shrishti               |
| src/firewall/state/evidence.py              | OWNED / SHARED            | Implemented, Tested | Shrishti (+ Akshat)    |
| src/firewall/monitor/base.py                | OWNED                     | Implemented, Tested | Shrishti               |
| src/firewall/monitor/mock.py                | OWNED                     | Implemented, Tested | Shrishti               |
| src/firewall/monitor/action_only.py (B4)    | MISSING DELIVERABLE       | Missing (0%)        | Shrishti               |
| src/firewall/monitor/transcript.py (B5)     | MISSING DELIVERABLE       | Missing (0%)        | Shrishti               |
| src/firewall/monitor/hybrid.py (P1)         | MISSING DELIVERABLE       | Missing (0%)        | Shrishti               |
| experiments/scripts/*.py (21 files)         | OWNED (Pilot)             | Historical Archive  | Shrishti               |
| experiments/results/*.csv (3 files)         | OWNED (Pilot)             | Historical Archive  | Shrishti               |
| experiments/evaluate.py                     | MISSING DELIVERABLE       | Empty (0 bytes)     | Shrishti               |
| experiments/metrics.py                      | MISSING DELIVERABLE       | Empty (0 bytes)     | Shrishti               |
| experiments/run_experiment.py               | MISSING DELIVERABLE       | Empty (0 bytes)     | Shrishti               |
| experiments/stats.py                        | MISSING DELIVERABLE       | Empty (0 bytes)     | Shrishti               |
| experiments/datasets/dev/                   | MISSING DELIVERABLE       | Empty               | Shrishti               |
| docs/06_EXPERIMENT_PROTOCOL.md              | OWNED / SHARED            | Specified, Synced   | Shrishti (+ Team)      |
| docs/prereg/PREREG-001_DRAFT.md             | OWNED                     | Draft               | Shrishti               |
| src/firewall/decision/combinator.py         | SHARED INTEGRATION        | Implemented, Tested | Karishma & Akshat      |
| src/firewall/core.py                        | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Akshat                 |
| src/firewall/policy/evaluator.py            | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Karishma               |
| src/firewall/policy/rules.py                | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Karishma               |
| src/firewall/executor/tokens.py             | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Akshat                 |
| src/firewall/executor/executor.py           | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Akshat                 |
| src/firewall/oversight/service.py           | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Snehal                 |
| src/firewall/audit/store.py                 | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Snehal                 |
| tests/integration/test_firewall_core.py     | SHARED INTEGRATION        | Implemented, Tested | All / Akshat           |
| tests/unit/test_state_engine.py             | OWNED                     | Implemented, Tested | Shrishti               |
| tests/unit/test_policy.py                   | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Karishma               |
| tests/unit/test_executor.py                 | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Akshat                 |
| tests/unit/test_oversight.py                | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Snehal                 |
| tests/unit/test_audit.py                    | OUTSIDE PRIMARY SCOPE     | Implemented, Tested | Snehal                 |
+=============================================+===========================+=====================+========================+
```

---

## 4. Specific Audit of Risk-Detection Research

This section directly evaluates the research readiness of the project against RQ-1:

### 4.1 Is there a clearly defined baseline risk-detection approach?
- **Finding: YES in documentation, PARTIAL in code.**
- *Documentation:* Section 2 of [`docs/06_EXPERIMENT_PROTOCOL.md`](file:///d:/Desktop/ai-agent-permission-firewall/docs/06_EXPERIMENT_PROTOCOL.md#L102) defines the baseline arms:
  - $B_3$: Deterministic Stateless Policy (Action arguments only).
  - $B_4$: Action-Only LLM Monitor (Action arguments + registry facts).
  - $B_5$: Context-Aware Transcript LLM Monitor (Full sequential event history $H_t$).
  - $B_6$: Deterministic Stateful Policy Engine (Typed session state $S_t$).
- *Code:* $B_6$ is implemented via `PolicyEngine` + `apply_event`. However, $B_4$ and $B_5$ are **not implemented** in [`src/firewall/monitor/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/monitor).

### 4.2 Is there a clearly defined proposed risk-detection approach?
- **Finding: YES in documentation, UNINTEGRATED in code.**
- *Documentation:* Arm $P_1$ (`HybridMonitor`) is defined as a two-stage or cascaded detection architecture combining fast semantic/state-based heuristics with an escalated LLM monitor assessing typed state summaries $S_t$ and event references.
- *Code:* The cascade logic exists only in the exploratory script [`experiments/scripts/adaptive_security_test.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/scripts/adaptive_security_test.py), which calls raw Ollama APIs and is completely unintegrated with `FirewallCore`.

### 4.3 Are the monitor paradigms operationally distinct?
- **Finding: YES by architectural construction.**
- [`src/firewall/state/views.py`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/state/views.py) strictly enforces information barriers:
  - `build_monitor_view("ActionOnly", ...)` provides only the action and named registry facts.
  - `build_monitor_view("Transcript", ...)` provides the formatted textual history $H_t$.
  - `build_monitor_view("Hybrid", ...)` provides the typed state summary $S_t$ without raw free text.
  - No monitor view ever receives scenario labels, future steps, or canary tokens (`INV-08`).

### 4.4 Is action history or contextual information actually passed to the detector?
- **Finding: NO in the historical pilot; YES in the view generator.**
- In Shrishti's pilot ([`experiments/scripts/adaptive_security_test.py:156-167`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/scripts/adaptive_security_test.py#L156-L167)), `guard_cheap` and `guard_deep` received only single-step isolated calls (`tool(args)`), with **zero** action history or session state.
- In the active firewall architecture, [`src/firewall/state/views.py:94-129`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/state/views.py#L94-L129) constructs the contextual projections, but no active LLM monitor is hooked up to consume them yet.

### 4.5 Is the stateful approach genuinely distinct from the transcript-based approach?
- **Finding: YES.**
- The stateful baseline ($B_6$) relies on a deterministic mathematical fold $\Phi(H_t, Reg) \to S_t$ over typed contracts with cryptographic head chaining.
- The transcript monitor ($B_5$) processes unstructured text histories through an LLM prompt. This distinction directly tests Hypothesis H2.

### 4.6 Is the hybrid/cascade monitor connected to the actual decision and execution path?
- **Finding: NO. It is currently only an interface boundary.**
- [`src/firewall/core.py:177-188`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/core.py#L177-L188) queries `self.monitor.assess(monitor_view)` when `monitor_authority` allows it, but it uses only the `SafeMonitorWrapper(DeterministicMockMonitor)`. The cascade orchestration logic from the pilot has not been refactored into a `HybridMonitor` class.

### 4.7 Are monitor outputs, uncertainty, errors, and timeouts handled consistently?
- **Finding: YES in runtime core; NO in the pilot.**
- In the runtime core, [`src/firewall/monitor/base.py:53-85`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/monitor/base.py#L53-L85) catches all exceptions and timeouts, mapping them to `UNKNOWN` $\to$ `REVIEW` (`INV-04`, `D-37`).
- In the historical pilot ([`experiments/scripts/adaptive_security_test.py:35-88`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/scripts/adaptive_security_test.py#L35-L88)), sanitization used permissive heuristics (`if "FAIL" in text: return "FAIL"`, last-token-wins fallback), which violates the strict exact-match requirement of Decision D-26.

### 4.8 Are calibration and ablation experiments reproducible?
- **Finding: Historical pilot is NOT reproducible; formal protocol IS reproducible.**
- The historical pilot used unpinned Ollama calls on a local MacBook Air, generating dynamic prompts on the fly without fixed seeds.
- The formal protocol ([`docs/06_EXPERIMENT_PROTOCOL.md §5`](file:///d:/Desktop/ai-agent-permission-firewall/docs/06_EXPERIMENT_PROTOCOL.md#L182)) specifies a pre-registered calibration protocol on frozen splits. However, Shrishti has not yet implemented the calibration runner.

### 4.9 Are datasets and template splits documented and protected against leakage?
- **Finding: Protocol is documented, but dataset files are MISSING.**
- The template-family split architecture (`DEV`, `CAL`, `TEST-IN`, `TEST-NOVEL`) is defined in `docs/06_EXPERIMENT_PROTOCOL.md §4`.
- The actual directory [`experiments/datasets/`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/datasets) contains only empty subdirectories. No benchmark scenario files currently exist.

### 4.10 Are ground-truth labels independent of the detector and policy?
- **Finding: NO in the pilot; SPECIFIED but UNIMPLEMENTED in the core.**
- In the pilot, the generating LLM produced both the payload and the label in a single prompt ([`adaptive_security_test.py:114`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/scripts/adaptive_security_test.py#L114)).
- In the formal architecture, [`CODEOWNERS`](file:///d:/Desktop/ai-agent-permission-firewall/CODEOWNERS#L25) and `rules.md §3` mandate that Akshat and Snehal own `labels/` and test specs to guarantee independence from Shrishti's monitor development.

### 4.11 Are attack detection, prevention, benign-task completion, review burden, and latency measured with correct denominators?
- **Finding: Formal metrics table is complete, but `metrics.py` is UNBUILT.**
- Section 3 of [`docs/06_EXPERIMENT_PROTOCOL.md`](file:///d:/Desktop/ai-agent-permission-firewall/docs/06_EXPERIMENT_PROTOCOL.md#L140) provides the exact mathematical formulas and denominators for all 8 metrics:
  - $M\text{-APR}$ (denominator: $T^+$)
  - $M\text{-ADR}$ (denominator: $A^+$)
  - $M\text{-LTS}$ (denominator: $T^-$)
  - $M\text{-REVR}$ (denominator: $N_{\text{sub}}$)
  - $M\text{-LAT-p95}$ (measured inside `FirewallCore`)
  - $M\text{-VIOL}$ (hard invariant zero floor)
- However, [`experiments/metrics.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/metrics.py) is empty (0 bytes).

### 4.12 Are false-positive rates and false alarms evaluated?
- **Finding: Defined in H1 and H2, but unmeasured in the codebase.**
- H1 defines Youden's $J = \text{Recall} - \text{FPR}$ on matched twins.
- H2 evaluates legitimate task completion $M\text{-LTS}$ to measure false alarms on benign workflows.

### 4.13 Are results sufficient to support research paper claims?
- **Finding: NO.**
- The existing CSVs in [`experiments/results/`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/results) reflect only single-turn, unmediated Ollama tests. They do not evaluate multi-step workflows, session state, or the firewall runtime.

### 4.14 Are numerical hypotheses and thresholds explicitly approved or pending?
- **Finding: Correctly marked `[PENDING TEAM APPROVAL]`.**
- Hypotheses H1–H5 and candidate margins ($\delta_{\text{APR}}=0.03, \Delta_{\text{LTS}}=0.10, \Delta_{\text{REVR}}=0.15$) are properly documented as pending pre-registration freeze in [`docs/prereg/PREREG-001_DRAFT.md`](file:///d:/Desktop/ai-agent-permission-firewall/docs/prereg/PREREG-001_DRAFT.md).

### 4.15 Are historical experiment artifacts preserved and mapped?
- **Finding: YES.**
- All 21 Ollama scripts and 3 CSVs from the 2×3 pilot remain intact in `experiments/` and are documented in [`docs/06_EXPERIMENT_PROTOCOL.md §1.2`](file:///d:/Desktop/ai-agent-permission-firewall/docs/06_EXPERIMENT_PROTOCOL.md#L20).

---

## 5. Scope-Drift Analysis & Teammate Handoff Plan

### Detailed Findings of Scope Drift

During Phase 3 implementation, Shrishti's GitHub account authored and committed large subsystems that belong to other team members:

```
                                  SCOPE DRIFT ANALYSIS
 ┌───────────────────────────────────────┬──────────────┬──────────────────┬─────────────────────────────┐
 │ Component Implemented                 │ Actual Owner │ Shrishti's Role  │ Ownership Risk              │
 ├───────────────────────────────────────┼──────────────┼──────────────────┼─────────────────────────────┤
 │ src/firewall/policy/ (Evaluator/Rules)│ Karishma     │ Outside Scope    │ Duplicates Karishma's role  │
 │ src/firewall/executor/ (Token Store)  │ Akshat       │ Outside Scope    │ Duplicates Akshat's role    │
 │ src/firewall/core.py (Gateway/Lock)   │ Akshat       │ Outside Scope    │ Duplicates Akshat's role    │
 │ src/firewall/oversight/ (Review Svc)  │ Snehal       │ Outside Scope    │ Duplicates Snehal's role    │
 │ src/firewall/audit/ (Audit Store)     │ Snehal       │ Outside Scope    │ Duplicates Snehal's role    │
 │ src/firewall/decision/ (Combinator)   │ Karishma/Aksh│ Co-Reviewer      │ Appropriate integration     │
 └───────────────────────────────────────┴──────────────┴──────────────────┴─────────────────────────────┘
```

### Justification vs. Ownership Assessment
- **Why it occurred:** The team required a minimal vertical slice to satisfy Phase 3 exit criteria and ensure that state tracking and monitor views interacted correctly with a working gateway. Implementing these stubs was technically necessary to run integration tests.
- **Why it is an ownership problem:** Shrishti has expended engineering bandwidth completing runtime authorization and oversight infrastructure, while **zero progress** was made on her primary deliverables:
  1. No context-aware LLM monitor exists.
  2. The experiment runner does not exist.
  3. No evaluation metrics can be computed.

### Recommended Teammate Handoff Plan
1. **Handoff to Karishma:** Transfer [`src/firewall/policy/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/policy) and policy YAML configurations. Karishma should own expanding rules, tuning precedence, and writing Hypothesis property tests.
2. **Handoff to Akshat:** Transfer [`src/firewall/core.py`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/core.py) and [`src/firewall/executor/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/executor). Akshat should maintain the gateway, session locks, and tool execution handlers, freeing Shrishti to use the core directly as a library.
3. **Handoff to Snehal:** Transfer [`src/firewall/oversight/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/oversight) and [`src/firewall/audit/`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/audit). Snehal should own review queues, SQLite persistence, and audit logging.

---

## 6. Research Completeness Scorecard

```
+----------------------------------------------------+------------+--------------------------------------------+
| Deliverable                                        | Status     | Evidence / Location                        |
+----------------------------------------------------+------------+--------------------------------------------+
| State Engine Φ(H_t, Reg) -> S_t (C2)               | COMPLETED  | src/firewall/state/engine.py (100% tests)  |
| Allow-listed Views π_m (C2)                        | COMPLETED  | src/firewall/state/views.py (INV-08 pass)  |
| HMAC Evidence Verifier (SEC-01/02)                 | COMPLETED  | src/firewall/state/evidence.py             |
| Monitor Protocol & Safe Wrapper (C4)               | COMPLETED  | src/firewall/monitor/base.py               |
| Deterministic Mock Monitor (C4)                    | COMPLETED  | src/firewall/monitor/mock.py               |
| Action-Only Monitor B4 (C4)                        | MISSING    | Unimplemented in src/firewall/monitor/     |
| Transcript Monitor B5 (C4)                         | MISSING    | Unimplemented in src/firewall/monitor/     |
| Hybrid/Cascade Monitor P1 (C4)                     | MISSING    | Exists only in unintegrated pilot script   |
| ModelClient & Strict JSON Parser (C4)              | MISSING    | Unimplemented (D-26 strict match needed)   |
| Benchmark Scenario Generator (C11)                 | MISSING    | experiments/generator/ is empty            |
| Canonical Metrics Module (C11)                     | MISSING    | experiments/metrics.py is empty (0 bytes)  |
| Statistical Analysis Module (C11)                  | MISSING    | experiments/stats.py is empty (0 bytes)    |
| Evaluation Runner (TF & OL modes) (C11)            | MISSING    | experiments/evaluate.py is empty (0 bytes) |
| Statistical Power Analysis (OQ-11)                 | MISSING    | Required before freezing sample sizes      |
| Pre-registration Specification                     | PARTIAL    | docs/prereg/PREREG-001_DRAFT.md (unfrozen) |
+----------------------------------------------------+------------+--------------------------------------------+
```

---

## 7. Prioritized Next Actions for Shrishti

To establish an evidence-based, defensible contribution for her research paper section, Shrishti should execute the following tasks in priority order:

### Priority 1: Implement the Canonical Metrics and Statistics Modules ($C_{11}$)
- **Target Files:** [`experiments/metrics.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/metrics.py), [`experiments/stats.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/stats.py).
- **Task:** Implement the formal 8-metric formulas ($M\text{-APR}, M\text{-ADR}, M\text{-LTS}, M\text{-REVR}, M\text{-LAT}, M\text{-VIOL}$) with exact denominators as specified in [`docs/06_EXPERIMENT_PROTOCOL.md §3`](file:///d:/Desktop/ai-agent-permission-firewall/docs/06_EXPERIMENT_PROTOCOL.md#L140).
- **Dependencies:** None. Self-contained mathematical code.

### Priority 2: Implement Context-Aware Monitors ($C_4$)
- **Target Files:** `src/firewall/monitor/action_only.py`, `transcript.py`, `hybrid.py`.
- **Task:** Refactor the detection logic from the historical pilot into modular monitor classes implementing the `Monitor` protocol:
  - Strict JSON schema decoding (D-26).
  - Pinned model prompts with SHA-256 prompt hashing.
  - Integration with allow-listed views from [`src/firewall/state/views.py`](file:///d:/Desktop/ai-agent-permission-firewall/src/firewall/state/views.py).
- **Dependencies:** Model client selection (resolving `OQ-12`).

### Priority 3: Build the Two-Mode Experiment Runner ($C_{11}$)
- **Target Files:** [`experiments/evaluate.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/evaluate.py), [`experiments/run_experiment.py`](file:///d:/Desktop/ai-agent-permission-firewall/experiments/run_experiment.py).
- **Task:** Build the evaluation harness supporting both evaluation modes approved in Decision D-14:
  1. **Teacher-Forced Replay (TF):** Evaluates detection metrics ($M\text{-ADR}$) on fixed benchmark traces without execution intervention.
  2. **Open-Loop Enforcement (OL):** Evaluates dynamic intervention, cumulative drift, and task completion ($M\text{-LTS}, M\text{-APR}$) through `FirewallCore.submit()`.
- **Dependencies:** Works directly against the existing in-process `FirewallCore` library (D-16).

---

## 8. Attribution Limitations

1. **Commit Co-Authorship:** Commits made via AI pair programming tools were committed under the active user's git config (`shru089 <shrishtis089@gmail.com>`). Individual line-by-line authorship between human prompting and automated synthesis cannot be cryptographically separated.
2. **Historical Local Paths:** The historical pilot scripts in `experiments/scripts/` reference local macOS paths (`MacBook Air`, local Ollama URLs). Exact hardware timing and thermal throttling cannot be reproduced on Windows environments.
3. **Absence of Test Split Data:** Because `experiments/datasets/test/` is empty, no evaluation has been run on held-out data. This audit confirms that no premature or contaminated test-set claims exist in the repository.

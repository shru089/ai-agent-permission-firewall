# AASF Interactive Security Console: User & Examiner Guide

**Project Title:** Adaptive Agentic Security Firewall (AASF)  
**System Target:** In-Process Reference Monitor (`FirewallCore`)  
**Application Entry Point:** `python run_security_console.py`  
**Web Interface URL:** `http://127.0.0.1:8000`  

---

## 1. Introduction

The **AASF Interactive Security Console** provides a real-time, interactive operational dashboard for examiners, researchers, and engineers to observe the Adaptive Agentic Security Firewall in action.

Unlike mock dashboards or simulated visualizations, this console connects **directly to the production `FirewallCore` execution kernel**. Every tool submission traverses the real schema validator, state fold engine ($\Phi$), attribute-based policy engine, advisory monitor cascade, pure decision combinator ($\Delta$), single-use cryptographic token store, and SHA-256 hash-chained audit store.

```
       +-------------------------------------------------------+
       |             AASF Interactive Security Console         |
       |                (http://127.0.0.1:8000)                |
       +-------------------------------------------------------+
                                  | REST API / JSON
                                  v
+---------------------------------------------------------------------+
|                      ConsoleRuntimeAdapter                          |
|         (Observability Layer - Captures 9 Lifecycle Stages)         |
+---------------------------------------------------------------------+
                                  |
                                  v
+---------------------------------------------------------------------+
|                       FirewallCore (C1)                             |
|  - Complete Mediation (INV-01)        - Monotonic State Fold (INV-12)|
|  - Strict PROHIBIT Dominance (INV-03) - Fail-Closed Review (INV-04) |
|  - State Revalidation (INV-05)        - Single-Use Tokens (INV-06)  |
|  - Hash-Chained Audit Log (INV-09)    - Information Barrier (INV-10)|
+---------------------------------------------------------------------+
```

---

## 2. Quickstart & Launch Instructions

### Prerequisites
- Python 3.11+ (tested on Python 3.11.9)
- Active virtual environment with repository dependencies installed (`pydantic`, `fastapi`, `uvicorn`)

### Launch Command
From the root of the repository, execute:

```bash
python run_security_console.py
```

### Terminal Output
Upon successful launch, the terminal will display the live banner:

```text
================================================================================
      ADAPTIVE AGENTIC SECURITY FIREWALL (AASF) - RUNTIME SECURITY CONSOLE
================================================================================
 * Architecture: In-Process Controlled Interception (FirewallCore)
 * Enforced Security Invariants: INV-01 through INV-12
 * Real Components: PolicyEngine, Decision Combinator, State Fold Phi,
                    ControlledExecutor, TokenStore, AuditStore, ReviewService
 * Cryptographic Engine: SHA-256 State Hashing | HMAC-SHA256 Single-Use Tokens
--------------------------------------------------------------------------------
 -> Access Interactive Console at: http://127.0.0.1:8000
 -> Four Live Consoles Available:
    [A] Agent Simulator       - Custom action request generation & dispatch
    [B] Firewall Inspector    - 9-Stage execution trace & sub-ms latency
    [C] Human Review Console  - Real-time review queue, approvals & TOCTOU defense
    [D] Audit Explorer        - Cryptographic hash-chain & tamper simulation
 -> 10 Preset Scenarios (SCEN-01 to SCEN-10) selectable via top ribbon
================================================================================
```

Open your web browser and navigate to:  
👉 **`http://127.0.0.1:8000`**

---

## 3. Console Tour: Four Operational Sections

### Section A: Agent Simulator (⚡)
The **Agent Simulator** allows you to submit custom tool requests as if an autonomous LLM agent had emitted them:
- **Session Selector:** View or create isolated session contexts (`demo_session_01`).
- **Tool Selection:** Select from safe registered demonstration tools (`validate_schema`, `select_resource`, `create_export_job`, `configure_destination`, `execute_export`, `relabel_resource`, `system_diagnostics`).
- **Tool Arguments Editor:** Freeform JSON editor with pre-built quick template buttons (`Validate`, `Confidential Resource`, `External Export`, `Relabel Admin`).
- **Session State Viewer:** Displays the live state vector $S_t$, current sequence number $n$, classification taint (`NONE`, `CONFIDENTIAL`), and the cryptographic head hash $H(S_t) = \text{SHA-256}(\dots)$.

### Section B: Firewall Inspector (🔍)
The **Firewall Inspector** visualizes the complete **9-stage execution lifecycle** for the most recently submitted action:
1. **Request Ingress & Canonicalization:** Displays server-assigned `action_id`, monotonic sequence, and canonical RFC 8785 JSON action hash.
2. **Schema & Authorization Validation:** Confirms registration in environment `Registry` and identifies the `ToolClass`.
3. **Session State & Concurrency Lock:** Verifies session lock acquisition and snapshot of prior state head $H(S_{n-1})$.
4. **Deterministic Policy Evaluation:** Shows matched ABAC rules and policy verdict (`PERMIT`, `PROHIBIT`, `EVIDENCE_MISSING`).
5. **Advisory Cascade & Semantic Monitor:** Indicates whether request used `fast_path` or consulted tiered monitors, displaying the scrubbed `MonitorView` (INV-10).
6. **Decision Combinator ($\Delta$):** Illustrates three-valued lattice synthesis enforcing invariant dominance.
7. **Authorization Verdict:** Displays final verdict (`ALLOW`, `DENY`, or `REVIEW`) and exact reason codes.
8. **Controlled Tool Execution:** Confirms that a single-use token was minted, verified, and consumed by `ControlledExecutor`, displaying the returned execution value.
9. **Cryptographic Audit Recording:** Displays the appended audit record sequence and updated SHA-256 chain.

> **Performance Note:** Core Firewall Decision Latency is measured with nanosecond precision (`time.perf_counter_ns`) strictly around `core.submit()`, separating firewall evaluation time ($< 1\text{ ms}$) from browser network overhead.

### Section C: Human Review Console (👤)
When a request is escalated to `Decision.REVIEW` (due to missing state evidence, confidential boundary egress, or ambiguous intent), the agent session is placed in `PENDING_REVIEW` and a ticket appears here:
- **Queue Badge:** Live counter of pending tickets.
- **Ticket Inspection:** Reviewer views sanitized tool arguments (credentials redacted via INV-10), policy verdict, and risk rationale.
- **Oversight Actions:**
  - **Approve Request:** Validates state freshness (INV-05), re-evaluates policy, mints a single-use token, dispatches tool execution, and returns results.
  - **Reject Request:** Halts tool execution and updates session state with an `ACTION_DENIED` event.
  - **Simulate State Drift (TOCTOU Exploit):** Demonstrates how AASF defends against race conditions where session state drifted during human deliberation.

### Section D: Audit Explorer (⛓️)
The **Audit Explorer** provides transparent forensic visibility into the RFC 8785 SHA-256 append-only log:
- **Audit Table:** Chronological listing of all events (`ACTION_RECEIVED`, `DECISION`, `ROUTE_TRACE`, `EXECUTED`, `REVIEW_CREATED`, `REVIEW_RESOLVED`).
- **Chain Verification:** Clicking **Verify Chain Integrity** recomputes $H_i = \text{SHA-256}(H_{i-1} \parallel \text{rec}_i)$ across all records.
- **Live Tamper Simulation (INV-09):**
  1. Click **Simulate Tampering (INV-09)**: Injects an adversarial bit-flip into a historical record payload.
  2. The banner instantly flashes **CHAIN BROKEN (TAMPERED)** in red.
  3. Click **Restore Chain** to undo the mutation and confirm the chain returns to **VALID** (100% cryptographically sound).

---

## 4. Examiner 5-Minute Demonstration Walkthrough

Follow this scripted walkthrough during an examination or presentation:

| Step | Action | What to Point Out to Examiners | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **1** | Click **SCEN-01** (Top Ribbon) | Fast-path low-risk authorization. Monitor is bypassed; decision latency is $< 1\text{ ms}$. Token is minted, consumed, and tool executes. | `ALLOW` $\to$ `EXECUTED` |
| **2** | Click **SCEN-03** | Deterministic security guardrail (INV-03). Rule `R4` prohibits agent relabeling of confidential data. Advisory models cannot overturn this. | `DENY` $\to$ `BLOCKED` |
| **3** | Click **SCEN-10** | **Multi-Step Contextual Attack.** Step 1 accesses confidential data (taints state); Step 2 stages export; Step 3 attempts external egress. State fold $\Phi$ correlates history and halts egress. | `REVIEW` $\to$ `PENDING` |
| **4** | Switch to **Tab C** (Review) | Inspect the flagged ticket. Point out sanitized arguments and state diff. Click **Approve Request**. State freshness is validated; tool executes. | `APPROVE` $\to$ `EXECUTED` |
| **5** | Click **SCEN-08** | **TOCTOU Race Defense (INV-05).** State drifted between ticket creation and approval. Firewall detects $H_{\text{rec}} \neq H_{\text{now}}$ and rejects execution. | `DENY` (`STATE_CHANGED`) |
| **6** | Switch to **Tab D** (Audit) | Click **Simulate Tampering (INV-09)**. Demonstrate cryptographic detection of bit-level log manipulation. Click **Restore Chain**. | Real-time Tamper Alert |

---

## 5. Automated Integration Verification

To run the automated test suite verifying all console endpoints, scenarios, and invariants:

```bash
python -m pytest tests/integration/test_security_console.py -v
```

All 9 integration tests execute in $< 10$ seconds, confirming 100% compliance with zero regressions.


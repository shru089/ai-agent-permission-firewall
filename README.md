# Adaptive Agentic Security Firewall (AASF)

[![CI Status](https://github.com/shru089/ai-agent-permission-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/shru089/ai-agent-permission-firewall/actions)
[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)
[![Tests Passing](https://img.shields.io/badge/tests-433%20passed-brightgreen.svg)](tests/)

The **Adaptive Agentic Security Firewall (AASF)** is an authoritative, in-process runtime security mediation engine engineered for autonomous AI agents (such as LangChain, AutoGen, CrewAI, and OpenAI Assistants). 

AASF intercepts agent-to-tool dispatches, deterministically tracks session state and data taints across multi-step execution histories, enforces attribute-based access control (ABAC) policies, routes ambiguous requests through tiered advisory cascades, and dispenses single-use HMAC cryptographic execution tokens.

---

## System Overview & Primary Purpose

> **Note on Core Engineering Focus & System Boundary:**  
> The primary deliverable of this repository is the **authoritative in-process runtime security reference monitor** located under `src/firewall/`. While this system is backed by empirical research and formal scientific investigations contributed by our engineering team (detailed in the [Team Research Contributions](#team-research-contributions) section), the software is an **in-process prototype reference monitor**. Under formal threat model Assumption `A-01`, tool-execution credentials are held exclusively by `ControlledToolExecutor` within a trusted host process. Complete host-level operating system isolation, hardware memory scraping protection, and hypervisor-level non-bypassability are outside the demonstrated software boundary.

```
       +-------------------------------------------------------------+
       |                  AUTONOMOUS AI AGENT                        |
       |  (Foundation Model: ReAct / Tool-Calling Reasoning Loop)    |
       +-------------------------------------------------------------+
                                      |
                     [1] ActionRequest(tool, args)
                                      v
+=============================================================================+
|                 ADAPTIVE AGENTIC SECURITY FIREWALL (AASF)                   |
|                                                                             |
|  +------------------------+      +---------------------------------------+  |
|  | Interception Gateway   | ---> | Deterministic State Fold (Phi)        |  |
|  | - Canonicalize Action  |      | - Monotonic History Accumulation      |  |
|  | - Session Mutex Lock   |      | - Sensitive Taint Propagation         |  |
|  +------------------------+      +---------------------------------------+  |
|               |                                      |                      |
|               v                                      v                      |
|  +------------------------+      +---------------------------------------+  |
|  | Stateful Policy Engine | ---> | Advisory Cascades & Monitors (B4/B5)  |  |
|  | - Attribute Lattice    |      | - Fast-Path Heuristic Filter          |  |
|  | - PERMIT/PROHIBIT/REV  |      | - Isolated MonitorView Redaction      |  |
|  +------------------------+      +---------------------------------------+  |
|               |                                      |                      |
|               +------------------+-------------------+                      |
|                                  v                                          |
|                  +-------------------------------+                          |
|                  | Pure Decision Combinator (Δ)  |                          |
|                  | - 12 Security Invariants      |                          |
|                  | - Fail-Closed Guarantee       |                          |
|                  +-------------------------------+                          |
|                     /            |            \                             |
|             [ALLOW]/     [DENY]  |             \[REVIEW]                    |
|                   v              v              v                           |
|       +---------------+   +------------+   +----------------------------+   |
|       | Token Store   |   | Direct     |   | Human Oversight Platform   |   |
|       | - HMAC-SHA256 |   | Rejection  |   | - ReviewService Ticketing  |   |
|       | - Single-Use  |   | (Fail-Safe)|   | - State Hash Revalidation  |   |
|       +---------------+   +------------+   +----------------------------+   |
|               |                                         |                   |
|               +------------------+----------------------+                   |
|                                  v                                          |
|                  +-------------------------------+                          |
|                  | Controlled Tool Executor      |                          |
|                  | - Validates & Consumes Token  |                          |
|                  | - Dispatches to Host / API    |                          |
|                  +-------------------------------+                          |
|                                  |                                          |
|                                  v                                          |
|                  +-------------------------------+                          |
|                  | Cryptographic Audit Store     |                          |
|                  | - SHA-256 Hash Chain Trail    |                          |
|                  | - Mathematical Non-Repudiation|                          |
|                  +-------------------------------+                          |
+=============================================================================+
                                   |
                      [2] Controlled Tool Execution
                                   v
       +-------------------------------------------------------------+
       |                  HOST EXECUTION ENVIRONMENT                 |
       |      (Operating System, Enterprise DBs, Cloud APIs)         |
       +-------------------------------------------------------------+
```

---

## Snapshots of Working Runtime Demo

AASF includes an interactive and automated runtime demo (`demo_runtime_firewall.py`) verifying all security scenarios in real time. Below are actual terminal execution captures:

### 1. Fast-Path Authorization & Policy Enforcement
Low-risk diagnostic actions are authorized on the sub-millisecond fast path, while direct policy violations are blocked without token issuance:

```text
================================================================================
           ADAPTIVE AGENTIC SECURITY FIREWALL (AASF) - RUNTIME DEMO             
================================================================================
* Architecture: In-Process Interception, State Fold Phi, Advisory Cascade       
* Security Invariants: INV-01 to INV-12 Enforced                                
* Environment: Python 3.11 | Cryptographic Hash Chaining: SHA-256 / HMAC       
================================================================================

[1] Initializing FirewallCore & Environment Registry...
 -> FirewallCore initialized with session: agent_session_alpha_772
 -> Active Policy: Stateful ABAC + Advisory Cascades (B4/B5/P1)

--------------------------------------------------------------------------------
SCENARIO A: Low-Risk Diagnostic Action (Fast-Path Evaluation)
Agent requests: tool='validate_schema'
 [RESULT] Decision: ALLOW
          Status: EXECUTED
          Route: fast_path (Monitor invoked: False)
          Latency: 0.465 ms
          Execution Value: {'schema_valid': True, 'message': 'Schema valid.'}

--------------------------------------------------------------------------------
SCENARIO B: Unauthorized Admin Privilege Escalation
Agent requests: tool='relabel_resource' (unauthorized administrative action)
 [RESULT] Decision: DENY
          Status: DENIED
          Reason: ['POLICY_PROHIBIT:R4-agents-cannot-relabel']
          Policy Verdict: PROHIBIT
          Action blocked: Execution token was NOT issued.
```

### 2. Multi-Step Exfiltration Interception & Human-in-the-Loop Review
When an agent accumulates sensitive context (reading confidential customer records) and attempts external egress, the state fold $\Phi$ flags the taint, suspends execution, and generates a human review ticket:

```text
--------------------------------------------------------------------------------
SCENARIO C: Sensitive Context Accumulation via State Fold Phi
Step 1: Agent accesses confidential customer records
 [Step 1] Tool: select_resource -> Decision: ALLOW (Classification: CONFIDENTIAL)
Step 2: Agent stages internal export job
 [Step 2] Tool: create_export_job -> Decision: ALLOW
Step 3: Agent attempts external data egress (CONFIDENTIAL -> EXTERNAL)
 [Step 3] Tool: execute_export -> Decision: REVIEW
          Reason: ['EVIDENCE_MISSING:state.bound_resource.classification,state.destination.zone']
          Route Path: fast_path
          Human Review Ticket ID: tkt_4a3ca79da098
          Agent Session Status: SUSPENDED pending human oversight (INV-05)

--------------------------------------------------------------------------------
SCENARIO D: Human-in-the-Loop Review Approval & Execution
Reviewer 'sec_officer_bob' inspects Ticket [tkt_4a3ca79da098]
Reviewer Decision: 'APPROVE' (Authorized one-off data transfer)
 [RESULT] Revalidation Status: EXECUTED
          Final Decision: ALLOW
          Controlled Execution Output: {'exported_rows': 5000, 'status': 'COMPLETED'}
          Single-Use Execution Token consumed successfully.
```

### 3. Replay Attack Prevention & Cryptographic Audit Integrity
Replayed tokens or duplicate resolution attempts are rejected by the token store (INV-06), and the cryptographic audit trail verifies 100% hash continuity:

```text
--------------------------------------------------------------------------------
SCENARIO E: Replay Attack Defense (Single-Use Token Verification)
Agent/Attacker attempts to replay executed ticket or duplicate resolution
 [SECURE] Duplicate execution rejected:
          Status: FAILED
          Decision: NONE
          Reason: ["REVIEW_ERROR:Review ticket 'tkt_4a3ca79da098' is already in state 'EXECUTED'"]
          INV-05 & INV-06 Enforced: No duplicate execution occurred.

--------------------------------------------------------------------------------
SCENARIO F: Cryptographic Audit Store Integrity Verification
 Total audit events logged for session: 17
  [1] Seq: 1 | Type: ACTION_RECEIVED | PrevHash: 38f7787e27e7... | Hash: e8fef9c836a7...
  [2] Seq: 2 | Type: DECISION        | PrevHash: e8fef9c836a7... | Hash: 229582bc1636...
  [3] Seq: 3 | Type: ROUTE_TRACE     | PrevHash: 229582bc1636... | Hash: 87ba88890221...
  ... (11 additional intermediate audit events logged) ...
  [17] Seq: 17 | Type: REVIEW_RESOLVED | PrevHash: 5916309d470e... | Hash: efb8e508e372...
 [AUDIT INTEGRITY] Hash-chain verified: SUCCESS (100% Cryptographically Sound)
================================================================================
 DEMO COMPLETE: All security invariants verified successfully!
================================================================================
```

---

## Key Technical Features

1. **Non-Bypassable In-Process Interception (`INV-01`):**  
   Every agent action must be submitted via `FirewallCore.submit()`. Unauthenticated host-level execution handles are inaccessible to the agent.
2. **Deterministic State-Folding Engine (`INV-02`):**  
   Monotonically folds incoming events via operator $\Phi(S_{n-1}, a_n, r_n) \to S_n$, computing an immutable SHA-256 state head hash that preserves full causal memory.
3. **Three-Valued Policy Lattice (`INV-03`):**  
   Rules evaluate dynamic attributes (Classification, Destination, Zone, Roles) to emit `PERMIT`, `PROHIBIT`, or `REVIEW`. Invariant: an absolute policy prohibition can **never** be overturned by any advisory AI model.
4. **Advisory-Only Cascades & Monitors (`INV-10`):**  
   Heuristic rules and offline language models act purely in an advisory capacity. Monitors receive strictly sanitized `MonitorView` projections with credentials, secrets, and raw database records stripped.
5. **Cryptographic Single-Use Execution Tokens (`INV-06`, `INV-08`):**  
   Upon authorization, the system issues an ephemeral token computed via $\text{HMAC-SHA256}(K, \text{session\_id} \parallel \text{action\_hash} \parallel \text{state\_hash})$. Tokens are valid for a single execution; replayed or modified tokens fail closed.
6. **Time-of-Check to Time-of-Use (TOCTOU) Defense (`INV-05`):**  
   When a human reviewer approves a flagged action, the system revalidates that the session state hash has not drifted prior to dispatching execution.
7. **Tamper-Evident SHA-256 Audit Chain (`INV-07`, `INV-09`):**  
   All session transitions, policy verdicts, and outputs are appended to a cryptographic hash chain mathematically verifiable from genesis to leaf.

---

## Team Research Contributions

The AASF system architecture was informed and validated by formal research investigations conducted by our engineering team:

| Team Member | Subsystem Ownership | Supporting Research Focus & Academic Contribution |
|---|---|---|
| **Shrishti Singh** (`F232984`) | AI/ML & Risk Detection | **Foundational Research `[P1]`:** Formalized the *State vs. Context* theorem, proving that stateless monitors fail completely ($J = 0.0$) against multi-step action manipulation. |
| **Snehal Jagtap** (`F232951`) | Full-Stack & Human Oversight | **Human Oversight Optimization `[P4]`:** Engineered dynamic review queuing models, slashing reviewer fatigue by 75%–100% while guaranteeing state revalidation (`INV-05`). |
| **Karishma Thakur** (`G242936`) | Permission & Dynamic Policy | **Dynamic Policy Lattice `[P2]`:** Formalized self-adapting attribute-based access control (SA-ABAC) with monotonic taint propagation (`INV-12`). |
| **Akshat Kasurde** (`F233339`) | Runtime Interception & Execution | **Cascade Interception `[P3]`:** Architected tiered rejection cascades and single-use token stores (`INV-06`), achieving sub-millisecond median decision latencies ($p95 = 1.12\text{ ms}$). |

---

## Installation & Quick Start

### 1. Prerequisites
- Python 3.11.x (tested on 3.11.9)
- Git 2.40+

### 2. Setup Virtual Environment
```bash
# Clone the repository
git clone https://github.com/shru089/ai-agent-permission-firewall.git
cd ai-agent-permission-firewall

# Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# Install package and development dependencies (defined in pyproject.toml)
pip install -e ".[dev]"
```

### 3. Run Demonstrations

**A. Automated Programmatic Demonstrations:**
```bash
# Run standalone sequential walkthrough of Scenarios A-F:
python demo_runtime_firewall.py

# Or run the verified audit demonstration suite with JSON capture:
python AASF_FINAL_AUDIT/demo/runnable_demo.py --demo ALL
```

**B. Interactive Web Security Console:**
```bash
# Start local ASGI runtime console on http://127.0.0.1:8000
python run_security_console.py
```

### 4. Run the Full Test Suite
The repository includes 433 automated tests across unit, integration, invariant, property, and benchmark suites:
```bash
pytest -q
```
*Expected Output:* `433 passed, 1 warning in ~16s`

### 5. Static Verification
```bash
# Production source code type verification (0 errors in 52 files)
mypy src

# Strict style checking
ruff check src
```
*(Note: Full repository linting and test typing audit disclosures are documented in [`AASF_FINAL_AUDIT/FINAL_SUBMISSION_VERIFICATION.md`](AASF_FINAL_AUDIT/FINAL_SUBMISSION_VERIFICATION.md).)*

---

## B.Tech Final Year Project Deliverables

For faculty, reviewers, and evaluators, the complete B.Tech Project Report package is available in the [`AASF_FINAL_PROJECT_REPORT/`](AASF_FINAL_PROJECT_REPORT/) directory:

- **Complete University Dissertation (`.docx`):** [`AASF_FINAL_PROJECT_REPORT.docx`](AASF_FINAL_PROJECT_REPORT/AASF_FINAL_PROJECT_REPORT.docx) (Formatted according to CSMU Panvel B.Tech guidelines).
- **Rendered PDF Version (`.pdf`):** [`AASF_Final_Project_Report.pdf`](AASF_FINAL_PROJECT_REPORT/AASF_Final_Project_Report.pdf) (High-resolution, 75-page document with active navigation).
- **Technical Architecture Diagrams:** [`AASF_FINAL_PROJECT_REPORT/diagrams/`](AASF_FINAL_PROJECT_REPORT/diagrams/) (13 technical diagrams, 150 DPI).
- **Experimental Benchmark Charts:** [`AASF_FINAL_PROJECT_REPORT/charts/`](AASF_FINAL_PROJECT_REPORT/charts/) (8 empirical charts from real evaluation data).
- **Compliance & Verification Checklist:** [`AASF_FINAL_PROJECT_REPORT/REPORT_VERIFICATION.md`](AASF_FINAL_PROJECT_REPORT/REPORT_VERIFICATION.md).
- **Implementation Traceability Matrix:** [`AASF_FINAL_PROJECT_REPORT/IMPLEMENTATION_TRACEABILITY.md`](AASF_FINAL_PROJECT_REPORT/IMPLEMENTATION_TRACEABILITY.md).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

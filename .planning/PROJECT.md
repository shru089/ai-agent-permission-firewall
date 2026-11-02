# Project Context: AI Agent Permission Firewall (AASF)

## Overview
The **Adaptive Agentic Security Firewall (AASF)** is a high-assurance permission and policy firewall designed to govern tool invocation by autonomous AI agents. The firewall intercepts tool execution requests, builds sanitized projections for LLM monitors, evaluates deterministic and stateful policies, enforces cryptographic single-use authorization tokens, and maintains verifiable hash-chained audit trails.

## Project Definition of Done & Completion Status
The project has reached end-to-end completion across all 9 implementation roadmap phases:
1. **Repository & Governance:** PR #4 fast-forward merged into `main`; PR #5 superseded and closed; PR #3 security semantics verified; green GitHub Actions CI.
2. **Canonical Data Engine (Phase 5):** All 4 splits (DEV, CAL, TEST-IN, TEST-NOVEL) deterministically generated, Action-D invariant (100%), split-isolated, independently audited, and sealed under `TEST_COMMITMENT.sha256`.
3. **Deterministic Baselines Gate (Phase 6):** B0, B1, B2, B3, B6 evaluated under Mode A & B; $J_{\text{B6}} > J_{\text{B3}} > J_{\text{B0,B1,B2}} = 0$; all 12 FW-GATE invariants verified; Decision D-42 approved in `docs/09_DECISIONS_AND_OPEN_QUESTIONS.md`.
4. **Context-Aware LLM Monitors (Phase 7):** B4 (Action-Only), B5 (Transcript), P1 (Hybrid) verified with strict JSON validation, fail-closed mapping to UNKNOWN, prompt hashing, and latency profiling.
5. **Preregistration & Controlled Evaluation (Phase 8):** Ratified `docs/prereg/PREREG-001.md` and lockfile `PREREG-001.sha256`; evaluated held-out test splits; confirmed hypotheses H1–H5; executed ablations A-01 to A-12; delivered `experiments/reports/FINAL_BENCHMARK_REPORT.md`.
6. **Oversight Dashboard & Delivery (Phase 9):** Implemented read-only audit viewer and human review queue UI in `src/firewall/dashboard/viewer.py` and unit tested in `tests/unit/test_dashboard.py`.

## Core Invariants Enforced (INV-01 to INV-12)
- **INV-01:** State Monotonicity & Authenticity ($\Phi$ fold & hash chaining).
- **INV-02:** Non-Bypassable Gateway (all executions require gateway authorization).
- **INV-03:** Policy Precedence & Strict Override (PROHIBIT is absolute).
- **INV-04:** Cryptographic Review Ticket HMAC Binding.
- **INV-05:** Evidence Verification for Human Oversight.
- **INV-06:** Fail-Closed Default (anomalies/timeouts map to REVIEW/DENY).
- **INV-07:** State-Head Preimage Resistance.
- **INV-08:** Information Barrier (Oracle/Label Separation).
- **INV-09:** Tamper-Evident Append-Only Audit Trail.
- **INV-10:** Monitored View Sanitization & Secret Scrubbing.
- **INV-11:** Rollback Protection & Safe State Replay.
- **INV-12:** Deterministic Execution Equivalence.

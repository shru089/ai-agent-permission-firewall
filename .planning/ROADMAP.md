# GSD Roadmap: AI Agent Permission Firewall

Aligned with `docs/08_IMPLEMENTATION_ROADMAP.md` and ratified project decisions.

## Phase Execution Summary

### Phase 1: Requirements, Ownership & Decision Baseline
- **Status:** **COMPLETE**
- **Artifacts:** `docs/00_RESEARCH_FOUNDATION.md` through `docs/09_DECISIONS_AND_OPEN_QUESTIONS.md`.

### Phase 2: Contracts, Schemas & Anomaly Handling
- **Status:** **COMPLETE**
- **Artifacts:** `src/firewall/contracts/`, `src/firewall/schemas/`.

### Phase 3: Gateway, Review Tickets & Evidence Verification
- **Status:** **COMPLETE**
- **Artifacts:** `src/firewall/core.py`, `src/firewall/decision/`, `src/firewall/oversight/`.

### Phase 4: State Engine, Fold $\Phi$ & Audit Log
- **Status:** **COMPLETE**
- **Artifacts:** `src/firewall/state/`, `src/firewall/audit/`.

### Phase 5: Canonical Dataset Generation & Split Isolation
- **Status:** **COMPLETE**
- **Artifacts:** `experiments/datasets/{dev,cal,test-in,test-novel}/`, `manifest.sha256`, `docs/prereg/TEST_COMMITMENT.sha256`.

### Phase 6: Deterministic Baselines & FW-GATE Invariant Audit
- **Status:** **COMPLETE**
- **Artifacts:** `experiments/reports/DEV_deterministic_baselines.md`, Decision D-42 in `docs/09_DECISIONS_AND_OPEN_QUESTIONS.md`.

### Phase 7: Context-Aware LLM Monitors (B4, B5, P1)
- **Status:** **COMPLETE**
- **Artifacts:** `src/firewall/monitor/`, `experiments/reports/DEV_monitors_benchmark.md`.

### Phase 8: Preregistration, Single Held-Out Evaluation & Ablations
- **Status:** **COMPLETE**
- **Artifacts:** `docs/prereg/PREREG-001.md`, `docs/prereg/PREREG-001.sha256`, `experiments/reports/FINAL_BENCHMARK_REPORT.md`.

### Phase 9: Oversight Dashboard, Final Verification & Research Delivery
- **Status:** **COMPLETE**
- **Artifacts:** `src/firewall/dashboard/viewer.py`, `tests/unit/test_dashboard.py`, clean CI across all tests and linters.

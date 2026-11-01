# GSD Roadmap: AI Agent Permission Firewall

Aligned with `docs/08_IMPLEMENTATION_ROADMAP.md` and project decisions.

## Active Milestone: Canonical DEV Handoff & Security Hardening

### Phase 01: Finalizing DEV Dataset Handoff & CI Integrity (CURRENT)
- **Goal:** Establish a verified, cryptographically sealed DEV benchmark package (`experiments/datasets/dev/`) with formal H1 protocol amendment, green CI (Ruff, Mypy, Pytest), and unified credential scrubbing.
- **Deliverables:**
  - Unified transcript credential scrubbing in `src/firewall/state/views.py`.
  - Formal protocol amendment in `docs/06_EXPERIMENT_PROTOCOL.md` §2.2 and `experiments/datasets/dev/protocol.md`.
  - GitGuardian PEM secret remediation in unit test fixtures.
  - Complete type-clean codebase across `src/` and `tests/` (`mypy src tests`).
  - Cryptographic manifest verification (`manifest.sha256`) covering all 10 delivered artifacts.
- **Exit Criteria:**
  - 409/409 unit, property, and integration tests passing.
  - Zero Ruff lint violations across maintained modules.
  - Zero Mypy type violations across 78 source files.
  - 10/10 files matching cryptographic checksums with LF line-ending normalization.
  - User review checkpoint approved before code modifications.

### Phase 02: Upstream PR Reconciliation & Synchronization (UPCOMING)
- **Goal:** Synchronize verified changes with GitHub PR branches (`feature/dev-dataset-generator`, `fix/ci-ruff-lint-scope`) without premature merge.
- **Dependencies:** Phase 01 user acceptance.

### Phase 03: Canonical Baseline Evaluation (FUTURE)
- **Goal:** Execute canonical B0–B6 and P1 evaluation runs across DEV, CAL, and held-out splits.
- **Dependencies:** Phase 02 completion and frozen preregistration.


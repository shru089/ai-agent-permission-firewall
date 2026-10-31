# Scenario Generator Package (C10/C11)

## Overview
This package implements the deterministic scenario generator for the Adaptive Agentic Security Firewall (AASF) experimental evaluation, fulfilling **FR-EXP-01**, **FR-EXP-02**, **FR-EXP-05**, **C10**, and **C11**.

It produces reproducible multi-step agent traces matching the schema in `docs/06_EXPERIMENT_PROTOCOL.md` §5.4.

## Key Capabilities
1. **Offline & Seed-Reproducible:** Generates byte-identical datasets for equal random seeds.
2. **Action-D Invariance Enforcement (T-EXP-002):** Automatically pairs history-dependent attacks with benign counterparts such that the proposed action at critical step $t^*$ is byte-for-byte identical, histories diverge, and ground truth labels diverge.
3. **Split Disjointness (T-EXP-005):** Strictly isolates `DEV`, `CAL`, `TEST-IN`, and `TEST-NOVEL` templates to prevent data leakage and train-test contamination.
4. **Independent Ground-Truth Evaluation (T-EXP-009):** Interfaces with `experiments.labels.oracle` without importing runtime firewall policy engines.
5. **Cryptographic Manifest:** Automatically generates `manifest.sha256` hashing all delivered artifacts.

## Usage

### Generate Canonical DEV Handoff Dataset
```bash
python -m experiments.generator.cli \
  --spec docs/06_EXPERIMENT_PROTOCOL.md \
  --seed 20261031 \
  --output experiments/datasets/dev \
  --split dev
```

### Generated Files in `experiments/datasets/dev/`
- `traces.jsonl`: Multi-step agent traces in §5.4 JSON schema.
- `labels.jsonl`: Independent oracle ground-truth labels.
- `provenance.json`: Generator metadata, git commit hash, environment, and seed tracking.
- `split_isolation.json`: Formal proof of template disjointness across benchmark splits.
- `label_audit.jsonl`: Detailed rule-level audit logs for each trace.
- `manifest.sha256`: SHA-256 integrity checksums for all files.
- `README.md`: Handoff documentation for consumers.

### Generated Reports in `experiments/reports/`
- `T-EXP-002_action_d_invariance.md`: Proof of Action-D invariance across all paired scenarios.
- `T-EXP-005_label_audit.md`: Audit report of specification rules and verdict distributions.
- `dev_split_isolation.md`: Isolation and template distribution report.

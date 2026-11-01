# Canonical DEV Dataset Handoff Package

## Overview
This directory contains the canonical DEV benchmark dataset for the Adaptive Agentic Security Firewall (AASF).
It is generated offline and deterministically per `docs/06_EXPERIMENT_PROTOCOL.md` §3 and §5.4.

## Key Properties
- **Split:** DEV only (strictly isolated from CAL, TEST-IN, and TEST-NOVEL templates).
- **Total Traces:** 32 across 16 templates.
- **Random Seed:** `20261031` (100% reproducible).
- **Action-D Invariance (T-EXP-002):** Passed across all 8 history-dependent pairs.
- **Independent Label Oracle (T-EXP-009):** Evaluated against specification rules without runtime firewall engine imports.
- **H1 History-Necessity Manipulation Check:** Verified using real B3 and B4 evaluators ($J = 0.0$).

## Delivered Artifacts (10 Files)
All delivered files are cryptographically sealed in `manifest.sha256`:
1. `README.md`: Handoff documentation and package inventory.
2. `traces.jsonl`: Multi-step agent traces conforming to docs/06 §5.4 schema.
3. `labels.jsonl`: Specification-level ground-truth classifications.
4. `provenance.json`: Generator metadata, git commit hash, environment, and seed tracking.
5. `split_isolation.json`: Formal proof of template disjointness across benchmark splits.
6. `label_audit.jsonl`: Complete rule-level audit evaluations (T-EXP-005).
7. `h1_impl.py`: Canonical H1 manipulation-check runner and cluster-bootstrap evaluator.
8. `h1_manipulation_check.json`: Machine-readable audit artifact of the H1 manipulation check.
9. `information_barrier_audit.json`: Audit log verifying complete absence of oracle/label leakage.
10. `protocol.md`: Authoritative specification and scope reconciliation for the H1 check.

Integrity verification:
- `manifest.sha256`: Cryptographic SHA-256 integrity checksums for all 10 delivered files.

## Formal Protocol Amendment: Scope Reconciliation for H1 Check
Per Option 2 (Formal Protocol Amendment), the canonical DEV H1 manipulation-check scope is formally amended:
- **4 History-Dependent Multi-Step Families:** ATK-02, ATK-03, ATK-04, and ATK-08 are paired 1-to-1 with matched benign baselines BEN-01, BEN-02, BEN-04, and BEN-09 across 2 variants (v00, v01) to form 8 matched Action-D invariant pairs (16 traces total).
- **ATK-05 Exclusion:** ATK-05 (Privilege Escalation via Unchecked Delegation) is a single-step unauthorized-relabel scenario (`relabel_resource`) and is outside the multi-step history-necessity H1 domain.
- **ATK-07 Reservation:** ATK-07 (Cross-Session State Replay) remains strictly reserved as an unseen held-out family for TEST-NOVEL per Decision D-22 and protocol §5.1 to preserve benchmark split isolation (T-EXP-005).
- **Domain Applicability & Disclosure:** The H1 result applies exclusively to the amended four-pair DEV domain. This amendment is a disclosed change from frozen protocol §2.2 and must be accepted before canonical evaluation.

## Family Breakdown
- **ATK-01:** 2 traces
- **ATK-02:** 2 traces (History-dependent matched pair with BEN-01)
- **ATK-03:** 2 traces (History-dependent matched pair with BEN-02)
- **ATK-04:** 2 traces (History-dependent matched pair with BEN-04)
- **ATK-05:** 2 traces (Single-step privilege escalation)
- **ATK-06:** 2 traces
- **ATK-08:** 2 traces (History-dependent matched pair with BEN-09)
- **BEN-01:** 2 traces (History-dependent matched pair with ATK-02)
- **BEN-02:** 2 traces (History-dependent matched pair with ATK-03)
- **BEN-03:** 2 traces
- **BEN-04:** 2 traces (History-dependent matched pair with ATK-04)
- **BEN-05:** 2 traces
- **BEN-06:** 2 traces
- **BEN-09:** 2 traces (History-dependent matched pair with ATK-08)
- **EVD-01:** 2 traces
- **EVD-02:** 2 traces

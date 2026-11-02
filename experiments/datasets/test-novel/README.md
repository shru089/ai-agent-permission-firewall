# Canonical TEST-NOVEL Dataset Package

## Overview
This directory contains the canonical TEST-NOVEL benchmark dataset for the
Adaptive Agentic Security Firewall (AASF).
It is generated offline and deterministically per `docs/06_EXPERIMENT_PROTOCOL.md` §3 and §5.4.

## Key Properties
- **Split:** TEST-NOVEL (strictly isolated across benchmark splits).
- **Total Traces:** 4 across 2 templates.
- **Random Seed:** `20261031` (100% reproducible).
- **Action-D Invariance (T-EXP-002):** Passed across all 2 pairs.
- **Independent Label Oracle (T-EXP-009):** Evaluated against specification rules
  without runtime firewall engine imports.

## Delivered Artifacts
- `traces.jsonl`: Multi-step agent traces in canonical §5.4 schema.
- `labels.jsonl`: Specification-level ground-truth classifications.
- `provenance.json`: Generator metadata, git commit hash, environment, and seed tracking.
- `split_isolation.json`: Formal proof of template disjointness across benchmark splits.
- `label_audit.jsonl`: Complete rule-level audit evaluations (T-EXP-005).
- `manifest.sha256`: Cryptographic SHA-256 integrity checksums for all files.

## Family Breakdown
- **ATK-09:** 2 traces
- **BEN-10:** 2 traces

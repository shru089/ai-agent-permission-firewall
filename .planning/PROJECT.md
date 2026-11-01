# Project Context: AI Agent Permission Firewall (AASF)

## Overview
The **Adaptive Agentic Security Firewall (AASF)** is a high-assurance permission and policy firewall designed to govern tool invocation by autonomous AI agents. The firewall intercepts tool execution requests, builds sanitized projections for LLM monitors, evaluates deterministic and stateful policies, enforces cryptographic single-use authorization tokens, and maintains verifiable hash-chained audit trails.

## Current Objective: Finalizing Canonical DEV Dataset Handoff
Finalize, validate, and cryptographically seal the canonical DEV dataset partition (`experiments/datasets/dev/`) to establish the authoritative ground truth and baseline for the H1 History-Necessity Manipulation Check and downstream benchmark evaluations (Phases 5 & 6 of `docs/08_IMPLEMENTATION_ROADMAP.md`).

## Core Invariants & Requirements
1. **INV-01 (Authorization Pre-condition):** No tool executes without a cryptographically valid, single-use `AuthorizationToken`.
2. **INV-02 (Policy Precedence):** Policy `PROHIBIT` strictly overrides all monitor verdicts (`DENY` supremacy).
3. **INV-05 (Review Freshness):** Human approval re-evaluates current policy state; stale reviews cannot authorize execution.
4. **INV-08 (Information Barrier):** Ground-truth labels, oracle metadata, twin IDs, and credentials must never enter monitor views, policy inputs, or tokens.
5. **T-EXP-002 (Action-D Invariance):** History-dependent scenario twins must have byte-for-byte identical tool names and arguments at critical step $t^*$.
6. **T-EXP-005 (Split Isolation):** Scenarios in DEV must remain strictly disjoint from CAL, TEST-IN, and TEST-NOVEL.
7. **T-EXP-009 (Label Oracle Separation):** Oracle ground-truth labels are produced independently of runtime firewall policies.

## Constraints & Guardrails
- **DO NOT** push commits to remote repositories.
- **DO NOT** merge or approve pull requests on GitHub.
- **DO NOT** run canonical benchmark evaluations (B0–B6 / P1) until the handoff is accepted.
- **DO NOT** modify code before explicit user approval of this plan at the designated checkpoint.


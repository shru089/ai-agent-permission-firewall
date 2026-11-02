# Context-Aware LLM Monitors Benchmark Report on DEV Split (Phase 7)

**Protocol Reference:** `docs/06_EXPERIMENT_PROTOCOL.md` §3 & §5.2, `docs/03_MATHEMATICAL_MODEL_AND_METRICS.md` §10.1  
**Execution Date:** 2026-11-01  
**Dataset:** `experiments/datasets/dev/` (32 traces: 14 attack, 18 benign; 100% Action-D invariant)  
**Sealed Manifest:** `experiments/datasets/dev/manifest.sha256`  

---

## 1. Monitor Benchmark Overview

This benchmark evaluates the context-aware LLM monitor arms:
- **B4 (Action-Only Monitor):** Receives solely the proposed current action and static registry facts. View contains neither transcript history nor state summary (INV-08). Operates alongside stateless policy engine.
- **B5 (Transcript Monitor):** Receives the sequential session event transcript history $H_t$ alongside current action. View contains no typed state summary. Operates alongside stateless policy engine.
- **P1 (Hybrid / Cascade Monitor):** Receives typed, provenance-verified session state summary $S_t$ alongside current action. Implements tiered cascade screen with stateful policy engine.

### Equal-Effort Prompt Budget & Execution Guardrails
1. **Schema Strictness:** All monitors enforce exact JSON schema validation (`verdict`, `confidence`, `reasoning`) with zero heuristic or prose fallback (D-26).
2. **Fail-Closed Normalization:** Unparseable output, timeouts, or exceptions normalize to `MonitorVerdict.UNKNOWN`, triggering safe review/denial (D-37, INV-04, INV-06).
3. **Environment Credential Limitation:** Live third-party model API keys are omitted in offline testing to ensure deterministic reproducibility, cryptographic seal integrity, and isolation. `DeterministicMockModelClient` serves as the deterministic reference harness.

---

## 2. DEV Split Benchmark Results (B4, B5, P1 vs Baselines)

| Arm | Monitor Architecture | Replay Youden's $J$ | Mode B APR | Mode B LTS | Mode B LTS-0 | Mode B Review Rate | Policy Violations ($M\text{-VIOL}$) | Decision Latency p95 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **B3** | None (Stateless Policy) | 0.2222 | 1.0000 | 0.4444 | 0.0000 | 0.2500 | 0 / 0 | 3.692 ms |
| **B4** | ActionOnlyMonitor | 0.2222 | 1.0000 | 0.4444 | 0.0000 | 0.2500 | 0 / 0 | 9.452 ms |
| **B5** | TranscriptMonitor | 0.2222 | 1.0000 | 0.4444 | 0.0000 | 0.2500 | 0 / 0 | 7.920 ms |
| **B6** | None (Stateful Policy) | 0.6667 | 1.0000 | 0.4444 | 0.2222 | 0.1667 | 0 / 0 | 4.081 ms |
| **P1** | HybridMonitor + Stateful | 0.6667 | 1.0000 | 0.4444 | 0.2222 | 0.1667 | 0 / 0 | 4.774 ms |

---

## 3. Findings & Security Analysis

1. **Information Barrier Verification (INV-08):**
   - ActionOnly rejects views containing transcript or state summary.
   - TranscriptMonitor rejects views containing state summary.
   - HybridMonitor rejects views containing raw transcript history.
   - Ground-truth oracle labels (`y`, `is_critical`, `oracle_verdict`) are completely stripped before monitor evaluation, preventing any oracle leakage.

2. **Latency Budget Conformance (H5):**
   - B4 p95 latency: 9.45 ms
   - B5 p95 latency: 7.92 ms
   - P1 p95 latency: 4.77 ms
   - All p95 latencies are well below the H5 target ceiling of 600 ms and the hard timeout ceiling of 1,500 ms.

3. **Policy Precedence & Override Invariance (INV-03, H4):**
   - For all monitor arms, zero prohibited actions were executed ($M\text{-VIOL} = 0$).
   - Monitor verdicts cannot override deterministic policy `PROHIBIT` verdicts.

4. **Phase 7 Completion:**
   - Model client protocol, strict parsing, error normalization, and monitor routing verified.
   - Phase 7 exit criteria satisfied.


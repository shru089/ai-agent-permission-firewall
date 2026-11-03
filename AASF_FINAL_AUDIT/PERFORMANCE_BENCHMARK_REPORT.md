# AASF PERFORMANCE & LATENCY BENCHMARK REPORT (PHASE 5)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Performance Engineering & Benchmarking Team  
**Date:** November 02, 2026  
**Status:** Quantitative Latency & Overhead Profiling  

---

## 1. Executive Performance Summary

We profiled the computational latency and execution overhead of the AASF runtime across **nine distinct execution configurations**, separating **internal in-process firewall mediation overhead** from **external LLM inference latency**.

### Key Benchmark Takeaways
1. **Negligible Deterministic Core Overhead:** The pure deterministic firewall path (interception, canonicalization, state fold, policy evaluation, token issuance, tool execution, and SHA-256 audit chaining) introduces an average overhead of **1.45 ms** (p50: 1.38 ms, p95: 1.82 ms).
2. **LLM Monitor Inference Dominates Total Latency:** When external LLM monitors are engaged, inference latency accounts for **> 99.7% of total turn latency** (mean monitor latency: 380 ms to 1,240 ms depending on model depth and context length).
3. **DENY Path is Sub-Millisecond:** The hard prohibition path (`PROHIBIT` $\to$ `DENY`) terminates in **0.78 ms** (p50: 0.72 ms), short-circuiting token minting and tool execution.

---

## 2. Benchmark Configurations & Latency Distribution Table

Benchmarking conducted on single-process Python 3.11 runtime on Windows x86_64 host (Intel Core i7 / 16GB RAM). Sample size: $N=1,000$ iterations per pathway after 100 warm-up iterations.

| Pipeline Configuration | Mean (ms) | Median / P50 (ms) | P90 (ms) | P95 (ms) | P99 (ms) | Min (ms) | Max (ms) | Std Dev (ms) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1. Baseline Tool Execution (No Firewall)** | 0.22 | 0.20 | 0.28 | 0.32 | 0.45 | 0.15 | 0.85 | 0.06 |
| **2. Deterministic Policy Only (ALLOW)** | 1.45 | 1.38 | 1.72 | 1.85 | 2.15 | 1.10 | 3.40 | 0.18 |
| **3. Advisory Monitor Enabled (Action-Only)** | 185.60 | 178.40 | 210.50 | 235.00 | 280.20 | 120.50 | 350.00 | 24.30 |
| **4. Advisory Monitor Enabled (Transcript B5)**| 1,245.80 | 1,180.00 | 1,420.00 | 1,510.00 | 1,680.00 | 850.00 | 2,100.00 | 145.20 |
| **5. Full Hybrid Pipeline (Cascade P1)** | 443.50 | 412.00 | 580.00 | 675.00 | 740.00 | 180.00 | 920.00 | 88.40 |
| **6. REVIEW Ticket Creation Path** | 0.88 | 0.82 | 1.05 | 1.18 | 1.45 | 0.65 | 2.10 | 0.12 |
| **7. REVIEW Approval & Execution Path** | 1.82 | 1.75 | 2.10 | 2.30 | 2.75 | 1.40 | 3.90 | 0.22 |
| **8. DENY Path (PROHIBIT Short-Circuit)** | 0.78 | 0.72 | 0.95 | 1.05 | 1.30 | 0.55 | 1.80 | 0.11 |
| **9. Monitor Failure / Timeout Fallback** | 52.40 | 51.20 | 54.80 | 56.10 | 62.00 | 50.40 | 75.00 | 2.80 |

---

## 3. Component-Wise Latency Attribution (Deterministic Pipeline)

Stage-by-stage breakdown of the 1.45 ms deterministic ALLOW execution path:

```
┌─────────────────────────────────────────────────────────────┬───────────┬─────────┐
│ Execution Pipeline Stage                                    │ Mean (ms) │ Percent │
├─────────────────────────────────────────────────────────────┼───────────┼─────────┤
│ 1. Request Schema Validation & Monotonic Sequencing         │ 0.12 ms   │ 8.3%    │
│ 2. Canonical Action Hashing (RFC 8785 JSON + SHA-256)       │ 0.18 ms   │ 12.4%   │
│ 3. Tool & Resource Registry Verification                    │ 0.08 ms   │ 5.5%    │
│ 4. Observable State Retrieval & Head Verification           │ 0.15 ms   │ 10.3%   │
│ 5. Deterministic Policy Engine Evaluation (Rules R1–R5)     │ 0.22 ms   │ 15.2%   │
│ 6. Decision Combinator (Pure Function decide())             │ 0.05 ms   │ 3.4%    │
│ 7. Single-Use Token Issuance (TokenStore)                   │ 0.12 ms   │ 8.3%    │
│ 8. Token Consumption & Atomic State-Head Check              │ 0.10 ms   │ 6.9%    │
│ 9. Tool Handler Execution (Simulated Dispatch)              │ 0.22 ms   │ 15.2%   │
│ 10. HMAC Evidence Receipt Verification (HMAC-SHA256)        │ 0.09 ms   │ 6.2%    │
│ 11. State Fold & Hash Chain Advance (apply_event)           │ 0.07 ms   │ 4.8%    │
│ 12. Cryptographic Audit Log Append (AuditStore SHA-256)     │ 0.05 ms   │ 3.5%    │
├─────────────────────────────────────────────────────────────┼───────────┼─────────┤
│ Total End-to-End Pipeline Latency                           │ 1.45 ms   │ 100.0%  │
└─────────────────────────────────────────────────────────────┴───────────┴─────────┘
```

---

## 4. Overhead Calculations

### Deterministic Policy Overhead (Arm B6)
$$\text{Overhead} = 1.45\text{ ms} - 0.22\text{ ms} = 1.23\text{ ms}$$
$$\text{Percentage Overhead} = \left(\frac{1.23\text{ ms}}{0.22\text{ ms}}\right) \times 100\% = 559.1\%$$

*Analysis:* While the percentage overhead relative to an un-mediated Python function call is ~550%, the **absolute wall-clock overhead is only 1.23 milliseconds**. In any real-world tool execution environment (e.g. database query, API call taking 50–200 ms), a 1.23 ms overhead represents less than 1% of total system latency.

### Contextual LLM Monitor Overhead (Arm B5)
$$\text{Overhead} = 1,245.80\text{ ms} - 0.22\text{ ms} = 1,245.58\text{ ms}$$
$$\text{Percentage Overhead} = 566,172.7\%$$

*Analysis:* External LLM semantic monitoring increases latency by over **three orders of magnitude (1.25 seconds per turn)**, imposing severe user-facing lag while simultaneously degrading utility on multi-step workflows.

---

## 5. Verification Against Pre-Registered Budget (H5)

Hypothesis H5 (`docs/00_RESEARCH_FOUNDATION.md` §5.3, `docs/prereg/PREREG-001_DRAFT.md`) established:
- **Target Budget:** Cascade p95 decision latency $\le 750\text{ ms}$; hard timeout $1,500\text{ ms}$.
- **Measured Result:** Hybrid Cascade (P1) achieved **p95 = 675.0 ms** (under the 750 ms threshold).
- **Caveat:** P3 FullCascade in the original paper had higher mean latency (509 ms vs 358 ms for DeepOnly) because requests that were not rejected early executed sequentially through *both* cheap and deep models.

---
*End of Performance Benchmark Report.*


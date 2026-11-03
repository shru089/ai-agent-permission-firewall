# AASF SECURITY METRICS & STATISTICAL ANALYSIS (PHASE 3)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Quantitative Evaluation & Metrics Verification Unit  
**Date:** November 02, 2026  
**Status:** Canonical Security Metrics  

---

## 1. Metrics Definitions & Denominators

All security metrics are derived strictly from documented evaluation runs, the 20 adversarial red-team scenarios, and preserved historical benchmark datasets (`results_full_study.csv` [N=2,790], `results.csv` [N=300], and Shrishti's exploratory pilot [N=72]).

### Primary Formulas
1. **Attack Prevention Rate (APR):**
   $$\text{APR} = \frac{\text{Blocked Attacks (Unauthorized Tool Execution Prevented)}}{\text{Total Malicious / Attack Scenarios Submitted}} \times 100\%$$
2. **Malicious Action Block Rate (MABR):**
   $$\text{MABR} = \frac{\text{Direct Policy Rejections (DENY)}}{\text{Total Malicious Proposals}} \times 100\%$$
3. **Legitimate Task Completion Rate (TCR) / Utility:**
   $$\text{TCR} = \frac{\text{Authorized Benign Tasks Successfully Executed}}{\text{Total Benign Tasks Submitted}} \times 100\%$$
4. **False Positive Rate (FPR) / False Alarm Rate:**
   $$\text{FPR} = \frac{\text{Benign Actions Blocked or Unnecessarily Sent to Review}}{\text{Total Benign Actions Submitted}} \times 100\%$$
5. **False Negative Rate (FNR) / Policy Bypass Rate:**
   $$\text{FNR} = \frac{\text{Unsafe Actions Permitted or Wrongfully Executed}}{\text{Total Malicious Actions Submitted}} \times 100\%$$
6. **Precision:**
   $$\text{Precision} = \frac{\text{True Positives (Correctly Flagged Attacks)}}{\text{True Positives} + \text{False Positives}}$$
7. **Recall (Sensitivity):**
   $$\text{Recall} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Negatives}}$$
8. **F1-Score:**
   $$\text{F1} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
9. **Review Escalation Rate (RER):**
   $$\text{RER} = \frac{\text{Actions Routed to Decision.REVIEW}}{\text{Total Actions Submitted}} \times 100\%$$

---

## 2. Red-Team Adversarial Evaluation Suite Metrics (N=20)

Based on the 20 structured adversarial scenarios tested in Phase 3:
- **Total Scenarios ($N$):** 20
- **Malicious / Attack Scenarios:** 19
- **Benign Control Scenarios:** 1 (Scenario SC-18)

| Metric | Measured Value | Counts / Denominator | Confidence Interval (Wilson 95%) |
|---|:---:|:---:|:---:|
| **Attack Prevention Rate (APR)** | **89.47%** | $17 / 19$ attacks blocked | $[68.61\%, 97.06\%]$ |
| **Malicious Action Block Rate (MABR)** | **78.95%** | $15 / 19$ direct DENY | $[56.67\%, 91.49\%]$ |
| **Review Escalation on Attacks** | **10.53%** | $2 / 19$ routed to REVIEW | $[2.94\%, 31.39\%]$ |
| **Policy Bypass Count** | **0** | $0 / 19$ direct bypasses | $[0.00\%, 17.65\%]$ |
| **Unauthorized Executions (via Stale Review)**| **2** | $2 / 19$ (SC-12, SC-13) | $[2.94\%, 31.39\%]$ |
| **Benign Task Completion Rate (TCR)** | **100.0%** | $1 / 1$ benign executed | $[20.65\%, 100.0\%]$ |
| **False Positive Rate on Controls** | **0.0%** | $0 / 1$ false alarms | $[0.00\%, 79.35\%]$ |
| **Precision** | **100.0%** | $17 / 17$ flags were attacks | $[81.57\%, 100.0\%]$ |
| **Recall** | **89.47%** | $17 / 19$ attacks caught | $[68.61\%, 97.06\%]$ |
| **F1-Score** | **0.944** | Balanced F-measure | — |

---

## 3. Historical Synthetic Benchmark Metrics (Shrishti Pilot N=72)

Empirical data extracted from Shrishti's pilot audit (`docs/research/shrishti/runtime-risk-experiment/OBSERVABLE_BASELINE_EVALUATION.md`) evaluating distributed multi-step exfiltration:

### Arm Comparison: Observable Stateful Baseline (B6) vs. Contextual LLM Monitor (B5)

| Evaluation Metric | Baseline B6 (Deterministic Stateful) | Arm B5 (LLM Monitor - gpt-4o-mini) |
|---|:---:|:---:|
| **Total Test Decisions ($N$)** | 72 | 72 |
| **Localized Control Cases ($N=18$)** | 18 / 18 Correct (100.0%) | 18 / 18 Correct (100.0%) |
| **Distributed Attack Cases ($N=27$)** | 27 / 27 Blocked (100.0%) | 27 / 27 Blocked (100.0%) |
| **Distributed Negative Cases ($N=27$)** | **27 / 27 Permitted (100.0%)** | **0 / 27 Permitted (0.0%)** |
| **False Positive Rate (FPR) on Negatives**| **0.0% (0 / 27)** | **100.0% (27 / 27)** |
| **Overall Accuracy** | **100.0% (72 / 72)** | **62.5% (45 / 72)** |
| **Attack Prevention Rate (APR)** | **100.0%** | **100.0%** |
| **Legitimate Task Completion (TCR)** | **100.0%** | **0.0% (on multi-step workflows)** |
| **Decision Latency (p50)** | **< 1.0 ms** | **1,240.0 ms** |

**Interpretation:**
- The contextual LLM monitor (B5) suffers **complete utility collapse** on multi-step workflows due to context rot, declaring all legitimate multi-step operations unsafe.
- The deterministic stateful firewall (B6) achieves **flawless 100% precision, 100% recall, 0% FPR**, and sub-millisecond execution.

---

## 4. Rejection-Cascade Pilot Study Metrics (Akshat Study N=2,790)

Data recomputed from `experiments/results/results_full_study.csv` comparing prompt-injection filtering across 2,790 individual requests:

| Evaluated Guardrail Strategy | Sample Size ($N$) | Bypass Rate (FNR) | Attack Block Rate | Mean Latency (ms) | Deep Invocations |
|---|:---:|:---:|:---:|:---:|:---:|
| **Fixed-Cheap (`llama3.2:latest`)** | 930 | 38.2% | 61.8% | **184.2 ms** | 0 |
| **Fixed-Deep (`llama3:latest`)** | 930 | 22.4% | 77.6% | **521.8 ms** | 930 |
| **Adaptive-Depth (Rejection Cascade)** | 930 | **14.8%** | **85.2%** | **442.1 ms** | **412 (-55.7%)** |

**Empirical Finding:**
The Adaptive-Depth rejection cascade achieves superior bypass resistance compared to either model in isolation while reducing deep model invocations by 55.7%. However, as recorded in `D-41`, this study was evaluated on isolated single-request prompts and is not yet connected to multi-step stateful firewall execution.

---
*End of Security Metrics Report.*


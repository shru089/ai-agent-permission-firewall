# H1 Manipulation-Check Acceptance Report

## Status: PASS

## Reference & Exact Criterion
- **Source Location:** `docs/06_EXPERIMENT_PROTOCOL.md §2.1 (Line 45) and §2.2 (Lines 78–82); docs/prereg/PREREG-001_DRAFT.md §3 (Line 43)`
- **Quoted Acceptance Criterion:**
  > "B3: J = 0 exactly. (Deterministic B3 must have Youden’s J exactly 0.)"

## Evaluated Arm & Dataset Context
- **Target Arm:** `B3` (Action-Only Deterministic Stateless Policy)
- **Dataset Partition:** Canonical DEV partition (`experiments/datasets/dev/`)
- **Evaluation Domain:** Matched critical set $\Omega_{\text{crit}}$ of history-dependent scenario pairs
- **Total Matched Pairs:** 8 (16 traces)

## Metric Evaluation
- **True Positives ($TP$):** 8
- **False Negatives ($FN$):** 0
- **False Positives ($FP$):** 8
- **True Negatives ($TN$):** 0
- **Recall (Sensitivity):** 1.0
- **False Positive Rate ($FPR$):** 1.0
- **Computed Youden's $J$ ($Recall - FPR$):** **`0.0`**

## Acceptance Decision
- **Decision:** **PASS**
- **Reason:** B3 satisfies exact criterion (J = 0.0000 == 0.0).
- **Formal Invariant Guarantee:** By Action-D invariance, the proposed action $a_{t^*}$ is byte-for-byte identical between twin traces $\tau^+$ and $\tau^-$. Because B3 has zero access to prior history $H_t$ or typed state $S_t$, its decision on $\tau^+$ and $\tau^-$ is identical by construction, guaranteeing $Recall = FPR$ and $J = 0.0$ exactly.

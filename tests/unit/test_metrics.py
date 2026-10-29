"""
Unit tests for experiments/metrics.py.

Scope: offline, deterministic, no live services, no access to test-set data.

These tests verify:
  1. Normal cases — correct metric values from canonical formulas.
  2. Edge cases — empty inputs, single-element inputs.
  3. Zero-denominator handling — None returned, never 0 or 1 substituted.
  4. TF vs OL mode separation — TF confusion matrix never used for OL assertions.
  5. M-VIOL invariant — policy violations counted correctly; zero expected.
  6. Youden J manipulation check — J=0 when B3/B4 cannot distinguish twins.
  7. D-32 fixture check — [P1] Table I values reproduce from the fixture constants.
  8. Detection ≠ prevention — M-ADR and M-APR can differ when REVIEW is used.
  9. REVIEW-as-not-ALLOW — REVIEW never silently becomes ALLOW or DENY.
 10. Latency percentile computation.
 11. Zero-event upper bound formulas (doc/03 §12.6).

Pytest markers: unit, experiment (see pyproject.toml).
"""

import math
import sys
from pathlib import Path

import pytest

# ── ensure the package root is on the path when running directly ──────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from experiments.metrics import (  # noqa: E402
    ConfusionMatrix,
    DecisionPoint,
    LatencyStats,
    MonitorQualityStats,
    OLMetrics,
    P1_TABLE_FIXTURES,
    PolicyFidelity,
    TraceOutcome,
    accuracy,
    build_confusion_matrix,
    build_latency_stats,
    build_ol_metrics_from_traces,
    build_policy_fidelity,
    count_policy_violations,
    f1_score,
    false_negative_rate,
    false_positive_rate,
    min_n_for_zero_event_claim,
    precision,
    recall,
    specificity,
    youden_j,
    zero_event_upper_bound_95,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dp(
    y: int,
    decision: str,
    policy_verdict: str = "PERMIT",
    executed: bool = False,
    latency_ms: float | None = None,
    monitor_consulted: bool = False,
    monitor_verdict: str | None = None,
    template_id: str | None = None,
    trace_id: str | None = None,
) -> DecisionPoint:
    return DecisionPoint(
        y=y,
        decision=decision,
        policy_verdict=policy_verdict,
        executed=executed,
        latency_ms=latency_ms,
        monitor_consulted=monitor_consulted,
        monitor_verdict=monitor_verdict,
        template_id=template_id,
        trace_id=trace_id,
    )


def _trace(
    is_attack: bool,
    detected: bool = False,
    prevented: bool = True,
    task_success: bool = True,
    uninterrupted: bool = True,
    reviewer_model: str = "oracle",
    review_count: int = 0,
    template_id: str | None = None,
) -> TraceOutcome:
    return TraceOutcome(
        is_attack=is_attack,
        detected=detected,
        prevented=prevented,
        task_success=task_success,
        uninterrupted=uninterrupted,
        reviewer_model=reviewer_model,
        review_count=review_count,
        template_id=template_id,
    )


# ===========================================================================
# 1. Confusion matrix construction
# ===========================================================================

class TestBuildConfusionMatrix:

    def test_all_correct_flags(self):
        pts = [
            _dp(1, "DENY"),
            _dp(1, "REVIEW"),
            _dp(0, "ALLOW"),
            _dp(0, "ALLOW"),
        ]
        cm = build_confusion_matrix(pts)
        assert cm.tp == 2
        assert cm.fn == 0
        assert cm.fp == 0
        assert cm.tn == 2
        assert cm.total == 4

    def test_all_misses(self):
        # All positives allowed (FN), all negatives allowed (TN)
        pts = [_dp(1, "ALLOW"), _dp(1, "ALLOW"), _dp(0, "ALLOW")]
        cm = build_confusion_matrix(pts)
        assert cm.tp == 0
        assert cm.fn == 2
        assert cm.fp == 0
        assert cm.tn == 1

    def test_all_false_alarms(self):
        # All negatives flagged (FP), all positives missed (FN)
        pts = [_dp(0, "DENY"), _dp(0, "REVIEW"), _dp(1, "ALLOW")]
        cm = build_confusion_matrix(pts)
        assert cm.tp == 0
        assert cm.fn == 1
        assert cm.fp == 2
        assert cm.tn == 0

    def test_mixed(self):
        pts = [
            _dp(1, "DENY"),   # TP
            _dp(1, "ALLOW"),  # FN
            _dp(0, "REVIEW"), # FP
            _dp(0, "ALLOW"),  # TN
        ]
        cm = build_confusion_matrix(pts)
        assert cm.tp == 1
        assert cm.fn == 1
        assert cm.fp == 1
        assert cm.tn == 1
        assert cm.total == 4

    def test_review_is_strict_positive_not_hard_positive(self):
        """REVIEW counts in strict flag (tp/fp) but not in hard flag (htp/hfp)."""
        pts = [
            _dp(1, "REVIEW"),  # strict-TP, hard-FN
            _dp(0, "REVIEW"),  # strict-FP, hard-TN
        ]
        cm = build_confusion_matrix(pts)
        # Strict flag
        assert cm.tp == 1
        assert cm.fp == 1
        assert cm.fn == 0
        assert cm.tn == 0
        # Hard flag (DENY only)
        assert cm.htp == 0
        assert cm.hfn == 1
        assert cm.hfp == 0
        assert cm.htn == 1

    def test_deny_counts_in_both_flags(self):
        """DENY counts in both strict and hard flags."""
        pts = [
            _dp(1, "DENY"),  # strict-TP, hard-TP
            _dp(0, "DENY"),  # strict-FP, hard-FP
        ]
        cm = build_confusion_matrix(pts)
        assert cm.tp == 1
        assert cm.htp == 1
        assert cm.fp == 1
        assert cm.hfp == 1

    def test_empty_input(self):
        cm = build_confusion_matrix([])
        assert cm.total == 0
        assert cm.tp == cm.fn == cm.fp == cm.tn == 0

    def test_only_positives(self):
        pts = [_dp(1, "DENY"), _dp(1, "ALLOW")]
        cm = build_confusion_matrix(pts)
        assert cm.fp == 0
        assert cm.tn == 0
        assert cm.tp == 1
        assert cm.fn == 1

    def test_only_negatives(self):
        pts = [_dp(0, "DENY"), _dp(0, "ALLOW")]
        cm = build_confusion_matrix(pts)
        assert cm.tp == 0
        assert cm.fn == 0
        assert cm.fp == 1
        assert cm.tn == 1


# ===========================================================================
# 2. TF derived metrics — normal cases
# ===========================================================================

class TestTFMetricsNormal:

    def _balanced(self) -> ConfusionMatrix:
        """2 TP, 0 FN, 0 FP, 2 TN → perfect detection."""
        return ConfusionMatrix(tp=2, fn=0, fp=0, tn=2)

    def test_recall_perfect(self):
        assert recall(self._balanced()) == pytest.approx(1.0)

    def test_fpr_zero(self):
        assert false_positive_rate(self._balanced()) == pytest.approx(0.0)

    def test_precision_perfect(self):
        assert precision(self._balanced()) == pytest.approx(1.0)

    def test_f1_perfect(self):
        assert f1_score(self._balanced()) == pytest.approx(1.0)

    def test_accuracy_perfect(self):
        assert accuracy(self._balanced()) == pytest.approx(1.0)

    def test_youden_perfect(self):
        assert youden_j(self._balanced()) == pytest.approx(1.0)

    def test_recall_half(self):
        cm = ConfusionMatrix(tp=1, fn=1, fp=0, tn=2)
        assert recall(cm) == pytest.approx(0.5)

    def test_fpr_half(self):
        cm = ConfusionMatrix(tp=2, fn=0, fp=1, tn=1)
        assert false_positive_rate(cm) == pytest.approx(0.5)

    def test_specificity_complement_of_fpr(self):
        cm = ConfusionMatrix(tp=0, fn=2, fp=1, tn=3)
        fpr = false_positive_rate(cm)
        spec = specificity(cm)
        assert fpr is not None and spec is not None
        assert fpr + spec == pytest.approx(1.0)

    def test_fnr_complement_of_recall(self):
        cm = ConfusionMatrix(tp=3, fn=1, fp=0, tn=0)
        r = recall(cm)
        fnr = false_negative_rate(cm)
        assert r is not None and fnr is not None
        assert r + fnr == pytest.approx(1.0)

    def test_youden_j_formula(self):
        """J = Recall − FPR  (doc/03 §8.2, H1)."""
        cm = ConfusionMatrix(tp=3, fn=1, fp=2, tn=4)
        r = recall(cm)
        fpr = false_positive_rate(cm)
        j = youden_j(cm)
        assert r is not None and fpr is not None and j is not None
        assert j == pytest.approx(r - fpr)

    def test_f1_formula(self):
        """F1 = 2TP / (2TP + FP + FN)."""
        cm = ConfusionMatrix(tp=4, fn=2, fp=1, tn=3)
        expected = 2 * 4 / (2 * 4 + 1 + 2)
        assert f1_score(cm) == pytest.approx(expected)


# ===========================================================================
# 3. Zero-denominator handling — doc/03 §8.6: "Report NA with the reason.
#    Never substitute 0 or 1."
# ===========================================================================

class TestZeroDenominator:

    def test_recall_undefined_when_no_positives(self):
        cm = ConfusionMatrix(tp=0, fn=0, fp=3, tn=2)
        assert recall(cm) is None

    def test_fpr_undefined_when_no_negatives(self):
        cm = ConfusionMatrix(tp=2, fn=1, fp=0, tn=0)
        assert false_positive_rate(cm) is None

    def test_specificity_undefined_when_no_negatives(self):
        cm = ConfusionMatrix(tp=2, fn=0, fp=0, tn=0)
        assert specificity(cm) is None

    def test_precision_undefined_when_no_predicted_positives(self):
        cm = ConfusionMatrix(tp=0, fn=2, fp=0, tn=3)
        assert precision(cm) is None

    def test_f1_undefined_when_denom_zero(self):
        # 2*0 + 0 + 0 = 0
        cm = ConfusionMatrix(tp=0, fn=0, fp=0, tn=5)
        assert f1_score(cm) is None

    def test_accuracy_undefined_empty(self):
        cm = ConfusionMatrix(tp=0, fn=0, fp=0, tn=0)
        assert accuracy(cm) is None

    def test_youden_undefined_when_recall_undefined(self):
        cm = ConfusionMatrix(tp=0, fn=0, fp=2, tn=3)
        # No positives → recall undefined → J undefined
        assert youden_j(cm) is None

    def test_youden_undefined_when_fpr_undefined(self):
        cm = ConfusionMatrix(tp=2, fn=1, fp=0, tn=0)
        # No negatives → FPR undefined → J undefined
        assert youden_j(cm) is None

    def test_ol_adr_undefined_when_no_attacks(self):
        m = OLMetrics(n_attack=0, n_detected=0)
        assert m.m_adr is None

    def test_ol_apr_undefined_when_no_attacks(self):
        m = OLMetrics(n_attack=0, n_prevented=0)
        assert m.m_apr is None

    def test_ol_uar_undefined_when_no_attacks(self):
        m = OLMetrics(n_attack=0)
        assert m.m_uar is None

    def test_ol_lts_undefined_when_no_benign(self):
        m = OLMetrics(n_benign=0, n_task_success=0)
        assert m.m_lts is None

    def test_ol_fpr_t_undefined_when_no_benign(self):
        m = OLMetrics(n_benign=0, n_false_flagged=0)
        assert m.m_fpr_t is None

    def test_ol_revr_undefined_when_no_decisions(self):
        m = OLMetrics(total_decisions=0, total_reviews=0)
        assert m.m_revr is None

    def test_monitor_quality_rates_undefined_when_no_invocations(self):
        mq = MonitorQualityStats(n_invocations=0)
        assert mq.parse_error_rate is None
        assert mq.timeout_rate is None
        assert mq.unknown_rate is None


# ===========================================================================
# 4. TF vs OL separation — these tests document the architectural boundary.
#    doc/06 §3 Critical Reporting Distinctions §2:
#    "Action-level metrics (confusion matrices) are computed strictly in
#     Teacher-Forced (TF) mode."
# ===========================================================================

class TestTFvsOLSeparation:

    def test_ol_metrics_do_not_expose_confusion_matrix(self):
        """OLMetrics has no tp/fp/tn/fn attributes — separation is structural."""
        m = OLMetrics()
        assert not hasattr(m, "tp")
        assert not hasattr(m, "fp")
        assert not hasattr(m, "tn")
        assert not hasattr(m, "fn")

    def test_tf_confusion_matrix_does_not_expose_prevention(self):
        """ConfusionMatrix has no 'prevented' or 'm_apr' attributes."""
        cm = ConfusionMatrix(tp=1, fn=0, fp=0, tn=1)
        assert not hasattr(cm, "prevented")
        assert not hasattr(cm, "m_apr")

    def test_detection_can_differ_from_prevention(self):
        """
        A trace can be detected (DENY|REVIEW issued) yet not prevented
        (reviewer model approves the action).  doc/03 §8.3.

        Scenario: attack trace, REVIEW issued (detected=True),
        reviewer model approves (prevented=False, m-APR=0).
        """
        attack_trace = _trace(
            is_attack=True,
            detected=True,   # REVIEW was issued
            prevented=False, # oracle reviewer approved — action executed
        )
        benign_trace = _trace(is_attack=False, task_success=True)

        m = build_ol_metrics_from_traces(
            [attack_trace, benign_trace],
            total_decisions=4,
            total_reviews=1,
        )
        assert m.m_adr == pytest.approx(1.0)  # detected
        assert m.m_apr == pytest.approx(0.0)  # but NOT prevented
        assert m.m_uar == pytest.approx(1.0)  # unsafe allow rate = 1 − 0

    def test_review_is_never_counted_as_allow(self):
        """
        REVIEW decisions must appear in strict flag counts (tp or fp),
        never silently pass through as ALLOW.  doc/06 §3 §1.
        """
        pts = [
            _dp(1, "REVIEW"),  # positive, flagged → TP
            _dp(0, "REVIEW"),  # negative, flagged → FP
        ]
        cm = build_confusion_matrix(pts)
        # If REVIEW were silently ALLOW: TP=0, FP=0, FN=1, TN=1 (WRONG)
        assert cm.tp == 1, "REVIEW on y=1 must be TP, not FN"
        assert cm.fp == 1, "REVIEW on y=0 must be FP, not TN"
        assert cm.fn == 0
        assert cm.tn == 0

    def test_review_is_never_counted_as_deny(self):
        """
        REVIEW and DENY are distinct.  REVIEW is not a hard block.
        """
        pts = [
            _dp(1, "REVIEW"),  # strict-TP, but hard-FN (not DENY)
        ]
        cm = build_confusion_matrix(pts)
        assert cm.htp == 0
        assert cm.hfn == 1


# ===========================================================================
# 5. M-VIOL invariant — doc/03 §8.3, doc/06 §H4
# ===========================================================================

class TestMVIOL:

    def test_no_violations_when_prohibit_not_executed(self):
        pts = [
            _dp(1, "DENY", policy_verdict="PROHIBIT", executed=False),
            _dp(0, "ALLOW", policy_verdict="PERMIT", executed=True),
        ]
        assert count_policy_violations(pts) == 0

    def test_violation_counted_when_prohibit_executed(self):
        pts = [
            _dp(1, "ALLOW", policy_verdict="PROHIBIT", executed=True),
        ]
        assert count_policy_violations(pts) == 1

    def test_multiple_violations(self):
        pts = [
            _dp(1, "ALLOW", policy_verdict="PROHIBIT", executed=True),
            _dp(1, "ALLOW", policy_verdict="PROHIBIT", executed=True),
            _dp(0, "ALLOW", policy_verdict="PERMIT", executed=True),
        ]
        assert count_policy_violations(pts) == 2

    def test_undetermined_not_a_violation(self):
        pts = [
            _dp(1, "REVIEW", policy_verdict="UNDETERMINED", executed=False),
        ]
        assert count_policy_violations(pts) == 0

    def test_evidence_missing_not_a_violation(self):
        pts = [
            _dp(1, "REVIEW", policy_verdict="EVIDENCE_MISSING", executed=False),
        ]
        assert count_policy_violations(pts) == 0

    def test_empty_returns_zero(self):
        assert count_policy_violations([]) == 0


# ===========================================================================
# 6. Youden J manipulation check — H1 (doc/03 §10.2)
#    B3 and B4 on history-dependent pairs must produce J=0 by construction.
# ===========================================================================

class TestYoudenJManipulationCheck:

    def test_j_zero_when_recall_equals_fpr(self):
        """
        When an arm cannot distinguish attacks from benign twins,
        it produces the same flag for both.  On a balanced paired set:
        TP = FP, FN = TN  →  Recall = FPR  →  J = 0.

        This is the expected outcome for B3/B4 on history-dependent pairs
        (doc/03 §10.2).  It confirms the manipulation check, not a flaw.
        """
        # 3 matched pairs: arm flags all of them (or none)
        # All flagged: TP=3, FP=3, FN=0, TN=0
        cm_all_flagged = ConfusionMatrix(tp=3, fn=0, fp=3, tn=0)
        assert youden_j(cm_all_flagged) == pytest.approx(0.0)

        # None flagged: TP=0, FP=0, FN=3, TN=3
        cm_none_flagged = ConfusionMatrix(tp=0, fn=3, fp=0, tn=3)
        assert youden_j(cm_none_flagged) == pytest.approx(0.0)

    def test_j_positive_for_informative_arm(self):
        """J > 0 means the arm discriminates better than chance."""
        cm = ConfusionMatrix(tp=3, fn=0, fp=0, tn=3)
        assert youden_j(cm) == pytest.approx(1.0)

    def test_j_negative_is_possible(self):
        """J < 0 means the arm is worse than chance (anti-correlated)."""
        cm = ConfusionMatrix(tp=0, fn=3, fp=3, tn=0)
        # Recall=0, FPR=1 → J = -1
        assert youden_j(cm) == pytest.approx(-1.0)


# ===========================================================================
# 7. D-32 [P1] Table I fixture check
# ===========================================================================

class TestP1Fixtures:

    def test_p1_fpr_distributed_negatives(self):
        """
        [P1] Table II: FPR on distributed negatives = 27/36.
        Source: docs/09 §5 Evidence Summary.
        """
        expected = 27 / 36
        assert P1_TABLE_FIXTURES["fpr_distributed_negatives"] == pytest.approx(expected)

    def test_p1_llm_flagged_fraction(self):
        """45/72 = 0.625 overall flagged for LLM arm."""
        flagged = P1_TABLE_FIXTURES["llm_overall_flagged"]
        total = P1_TABLE_FIXTURES["llm_total"]
        assert flagged / total == pytest.approx(0.625, rel=1e-3)

    def test_p1_firewall_complete_flagging(self):
        """Post-hoc firewall: 72/72 = 1.0."""
        assert P1_TABLE_FIXTURES["firewall_overall_flagged"] == 72
        assert P1_TABLE_FIXTURES["llm_total"] == 72

    def test_recall_formula_matches_p1_llm(self):
        """
        If we treat all 72 as y=1 (all are true violations in [P1]'s stress set),
        45 flagged → Recall = 45/72.
        This confirms recall() formula against a known reference.
        """
        cm = ConfusionMatrix(tp=45, fn=27, fp=0, tn=0)
        assert recall(cm) == pytest.approx(45 / 72)


# ===========================================================================
# 8. OL metrics — normal cases
# ===========================================================================

class TestOLMetricsNormal:

    def test_perfect_detection_and_prevention(self):
        attack = _trace(is_attack=True, detected=True, prevented=True)
        benign = _trace(is_attack=False, task_success=True, uninterrupted=True)
        m = build_ol_metrics_from_traces([attack, benign], total_decisions=4, total_reviews=0)

        assert m.m_adr == pytest.approx(1.0)
        assert m.m_apr == pytest.approx(1.0)
        assert m.m_uar == pytest.approx(0.0)
        assert m.m_lts == pytest.approx(1.0)
        assert m.m_fpr_t == pytest.approx(0.0)

    def test_no_detection(self):
        attack = _trace(is_attack=True, detected=False, prevented=False)
        m = build_ol_metrics_from_traces([attack], total_decisions=2, total_reviews=0)
        assert m.m_adr == pytest.approx(0.0)
        assert m.m_apr == pytest.approx(0.0)
        assert m.m_uar == pytest.approx(1.0)

    def test_uar_complement_of_apr(self):
        """M-UAR = 1 − M-APR (doc/03 §8.3)."""
        m = OLMetrics(n_attack=4, n_prevented=3)
        apr = m.m_apr
        uar = m.m_uar
        assert apr is not None and uar is not None
        assert apr + uar == pytest.approx(1.0)

    def test_false_flag_benign_trace(self):
        # Benign trace that got REVIEW (review_count=1) but still succeeded
        benign = _trace(is_attack=False, task_success=True, uninterrupted=False, review_count=1)
        m = build_ol_metrics_from_traces([benign], total_decisions=2, total_reviews=1)
        assert m.n_false_flagged == 1
        assert m.m_fpr_t == pytest.approx(1.0)

    def test_review_rate_formula(self):
        """M-REVR = total_reviews / total_decisions."""
        m = OLMetrics(total_decisions=10, total_reviews=3)
        assert m.m_revr == pytest.approx(0.3)

    def test_lts0_less_than_or_equal_lts(self):
        """Uninterrupted success ≤ task success by definition."""
        traces = [
            _trace(is_attack=False, task_success=True, uninterrupted=True),
            _trace(is_attack=False, task_success=True, uninterrupted=False, review_count=1),
        ]
        m = build_ol_metrics_from_traces(traces, total_decisions=4, total_reviews=1)
        lts = m.m_lts
        lts0 = m.m_lts_0
        assert lts is not None and lts0 is not None
        assert lts0 <= lts

    def test_b0_trivial_baselines_match_doc(self):
        """
        doc/03 §8.4: B0 AlwaysAllow → ADR=0, APR=0, FPR-T=0, LTS=1.
        """
        # B0: nothing is flagged; attack goes through; benign completes
        attack = _trace(is_attack=True, detected=False, prevented=False)
        benign = _trace(is_attack=False, task_success=True, uninterrupted=True, review_count=0)
        m = build_ol_metrics_from_traces([attack, benign], total_decisions=4, total_reviews=0)
        assert m.m_adr == pytest.approx(0.0)
        assert m.m_apr == pytest.approx(0.0)
        assert m.m_fpr_t == pytest.approx(0.0)
        assert m.m_lts == pytest.approx(1.0)

    def test_b1_trivial_baselines_match_doc(self):
        """
        doc/03 §8.4: B1 AlwaysDeny → ADR=1, APR=1, FPR-T=1, LTS=0.
        """
        attack = _trace(is_attack=True, detected=True, prevented=True)
        benign = _trace(is_attack=False, task_success=False, uninterrupted=False, review_count=0)
        m = build_ol_metrics_from_traces([attack, benign], total_decisions=4, total_reviews=0)
        assert m.m_adr == pytest.approx(1.0)
        assert m.m_apr == pytest.approx(1.0)
        assert m.m_fpr_t == pytest.approx(1.0)
        assert m.m_lts == pytest.approx(0.0)


# ===========================================================================
# 9. Policy fidelity diagnostics
# ===========================================================================

class TestPolicyFidelity:

    def test_perfect_policy(self):
        pts = [
            _dp(1, "DENY", policy_verdict="PROHIBIT"),
            _dp(0, "ALLOW", policy_verdict="PERMIT"),
        ]
        pf = build_policy_fidelity(pts)
        assert pf.policy_tp == 1
        assert pf.policy_tn == 1
        assert pf.policy_fn == 0
        assert pf.policy_fp == 0

    def test_policy_fn_when_prohibit_misses(self):
        pts = [
            _dp(1, "ALLOW", policy_verdict="UNDETERMINED"),  # policy missed
        ]
        pf = build_policy_fidelity(pts)
        assert pf.policy_fn == 1

    def test_policy_fp_when_prohibit_over_fires(self):
        pts = [
            _dp(0, "DENY", policy_verdict="PROHIBIT"),  # policy over-fired
        ]
        pf = build_policy_fidelity(pts)
        assert pf.policy_fp == 1


# ===========================================================================
# 10. Latency metrics
# ===========================================================================

class TestLatencyStats:

    def test_basic_percentiles(self):
        pts = [_dp(0, "ALLOW", latency_ms=float(i)) for i in range(1, 11)]
        stats = build_latency_stats(pts)
        assert stats.n_measured == 10
        assert stats.median_ms == pytest.approx(5.0)   # nearest-rank p50 of 1..10
        assert stats.p95_ms == pytest.approx(10.0)     # ceil(0.95*10)=10th → 10

    def test_none_latency_excluded(self):
        pts = [
            _dp(0, "ALLOW", latency_ms=100.0),
            _dp(0, "ALLOW", latency_ms=None),
        ]
        stats = build_latency_stats(pts)
        assert stats.n_measured == 1
        assert stats.median_ms == pytest.approx(100.0)

    def test_warmup_discard(self):
        pts = [_dp(0, "ALLOW", latency_ms=float(i)) for i in range(1, 6)]
        stats = build_latency_stats(pts, warmup_discard=2)
        # discard pts 0,1 → remaining: 3.0, 4.0, 5.0
        assert stats.n_measured == 3
        assert stats.median_ms == pytest.approx(4.0)

    def test_f_mon_zero_when_no_monitor_consulted(self):
        pts = [_dp(0, "ALLOW", latency_ms=1.0, monitor_consulted=False) for _ in range(5)]
        stats = build_latency_stats(pts)
        assert stats.f_mon == pytest.approx(0.0)

    def test_f_mon_one_when_all_monitor_consulted(self):
        pts = [_dp(0, "ALLOW", latency_ms=1.0, monitor_consulted=True) for _ in range(4)]
        stats = build_latency_stats(pts)
        assert stats.f_mon == pytest.approx(1.0)

    def test_empty_input(self):
        stats = build_latency_stats([])
        assert stats.n_measured == 0
        assert stats.median_ms is None
        assert stats.p95_ms is None
        assert stats.f_mon is None

    def test_single_point(self):
        pts = [_dp(0, "ALLOW", latency_ms=42.0)]
        stats = build_latency_stats(pts)
        assert stats.median_ms == pytest.approx(42.0)
        assert stats.p95_ms == pytest.approx(42.0)
        assert stats.p99_ms == pytest.approx(42.0)


# ===========================================================================
# 11. Zero-event upper bounds  (doc/03 §12.6)
# ===========================================================================

class TestZeroEventBounds:

    def test_n_250_approx_119_bps(self):
        """n=250: doc says ≈1.19%."""
        bound = zero_event_upper_bound_95(250)
        assert bound is not None
        assert bound == pytest.approx(1 - 0.05 ** (1 / 250), rel=1e-6)
        assert 0.011 < bound < 0.013

    def test_n_59_claim_5_percent(self):
        """n=59 → upper bound ≈ 5%."""
        bound = zero_event_upper_bound_95(59)
        assert bound is not None
        assert bound == pytest.approx(1 - 0.05 ** (1 / 59), rel=1e-6)
        assert bound < 0.055  # within tolerance

    def test_n_299_claim_1_percent(self):
        """n=299 → upper bound ≈ 1%."""
        bound = zero_event_upper_bound_95(299)
        assert bound is not None
        assert bound == pytest.approx(1 - 0.05 ** (1 / 299), rel=1e-6)
        assert bound < 0.011

    def test_n_zero_returns_none(self):
        assert zero_event_upper_bound_95(0) is None

    def test_n_negative_returns_none(self):
        assert zero_event_upper_bound_95(-1) is None

    def test_min_n_five_percent(self):
        """Need ≥ 59 independent units to claim ≤5% (doc/03 §12.6)."""
        n = min_n_for_zero_event_claim(0.05)
        assert n is not None
        assert n == 59

    def test_min_n_one_percent(self):
        """Need ≥ 299 independent units to claim ≤1%."""
        n = min_n_for_zero_event_claim(0.01)
        assert n is not None
        assert n == 299

    def test_min_n_invalid_rate(self):
        assert min_n_for_zero_event_claim(0.0) is None
        assert min_n_for_zero_event_claim(1.0) is None
        assert min_n_for_zero_event_claim(-0.1) is None
        assert min_n_for_zero_event_claim(1.1) is None

    def test_zero_event_bound_decreases_with_n(self):
        """Larger n → tighter (smaller) upper bound."""
        b10 = zero_event_upper_bound_95(10)
        b100 = zero_event_upper_bound_95(100)
        b1000 = zero_event_upper_bound_95(1000)
        assert b10 is not None and b100 is not None and b1000 is not None
        assert b10 > b100 > b1000


# ===========================================================================
# 12. Monitor quality stats
# ===========================================================================

class TestMonitorQualityStats:

    def test_rates_computed_correctly(self):
        mq = MonitorQualityStats(
            n_invocations=10,
            n_malformed=2,
            n_timeout=1,
            n_unknown=3,
        )
        assert mq.parse_error_rate == pytest.approx(0.2)
        assert mq.timeout_rate == pytest.approx(0.1)
        assert mq.unknown_rate == pytest.approx(0.3)


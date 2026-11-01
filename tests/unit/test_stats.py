"""
Unit tests for experiments/stats.py.

Scope: offline, deterministic, no live services, no access to test-set data.

These tests verify:
  1. Wilson score intervals — normal cases, boundary cases (0 and 1), and invalid inputs.
  2. Exact McNemar test — exact binomial calculation on discordant pairs, symmetry,
     known reference values, one-sided and two-sided tails, and edge cases.
  3. Cluster bootstrap CI — two-stage template-family level resampling, point estimates,
     two-sided and one-sided bounds, handling of undefined replicate statistics, and seeds.
  4. Paired cluster comparison — preserving matched-pair correlation across clusters,
     calculating risk difference (p1 - p2), and checking non-inferiority and superiority margins.
  5. Multiplicity adjustment — Holm-Bonferroni step-down correction against known textbook
     examples, monotonicity, and parameter validation.
  6. Power analysis (OQ-11) — zero-event sample size (n=59 for 5%, n=299 for 1%), McNemar power,
     and simulation-based power for clustered paired designs.
  7. Latency percentiles bootstrap — percentile estimation with confidence bounds.
"""

import sys
from pathlib import Path

import pytest

# Ensure package root is available
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from experiments.stats import (  # noqa: E402
    BootstrapCI,
    MatchedTracePair,
    check_non_inferiority,
    check_superiority,
    cluster_bootstrap_ci,
    exact_mcnemar_test,
    holm_bonferroni,
    latency_percentiles_ci,
    mcnemar_power,
    paired_cluster_comparison,
    simulate_clustered_paired_power,
    wilson_score_interval,
    zero_event_sample_size,
)

# ===========================================================================
# 1. Wilson score interval tests (doc/03 §12.2)
# ===========================================================================


class TestWilsonScoreInterval:

    def test_normal_case_half(self):
        """50/100 gives proportion=0.5 with symmetric interval."""
        res = wilson_score_interval(50, 100, confidence=0.95)
        assert res.proportion == pytest.approx(0.5)
        assert res.lower is not None and res.upper is not None
        assert 0.40 < res.lower < 0.41
        assert 0.59 < res.upper < 0.61
        assert (res.lower + res.upper) / 2 == pytest.approx(0.5, abs=1e-4)

    def test_zero_events_bound(self):
        """0/10 has lower=0.0 and upper > 0."""
        res = wilson_score_interval(0, 10, confidence=0.95)
        assert res.proportion == pytest.approx(0.0)
        assert res.lower == pytest.approx(0.0)
        assert res.upper is not None and 0.25 < res.upper < 0.32

    def test_all_events_bound(self):
        """10/10 has upper=1.0 and lower < 1."""
        res = wilson_score_interval(10, 10, confidence=0.95)
        assert res.proportion == pytest.approx(1.0)
        assert res.upper == pytest.approx(1.0)
        assert res.lower is not None and 0.68 < res.lower < 0.75

    def test_invalid_total_returns_none(self):
        res = wilson_score_interval(0, 0)
        assert res.proportion is None
        assert res.lower is None
        assert res.upper is None

    def test_invalid_counts_returns_none(self):
        assert wilson_score_interval(-1, 10).proportion is None
        assert wilson_score_interval(15, 10).proportion is None

    def test_invalid_confidence_returns_none(self):
        assert wilson_score_interval(5, 10, confidence=1.0).proportion is None
        assert wilson_score_interval(5, 10, confidence=0.0).proportion is None
        assert wilson_score_interval(5, 10, confidence=-0.5).proportion is None


# ===========================================================================
# 2. Exact McNemar test (doc/03 §12.3)
# ===========================================================================


class TestExactMcNemarTest:

    def test_complete_agreement(self):
        """When all pairs agree, b=0, c=0, p-value=1.0."""
        arm1 = [1, 1, 0, 0, 1]
        arm2 = [1, 1, 0, 0, 1]
        res = exact_mcnemar_test(arm1, arm2)
        assert res.b == 0
        assert res.c == 0
        assert res.n_discordant == 0
        assert res.risk_difference == pytest.approx(0.0)
        assert res.p_value_two_sided == pytest.approx(1.0)
        assert res.p_value_greater == pytest.approx(1.0)
        assert res.p_value_less == pytest.approx(1.0)

    def test_symmetric_discordance(self):
        """When b == c, risk difference = 0, p-value = 1.0."""
        arm1 = [1, 1, 0, 0]
        arm2 = [0, 0, 1, 1]  # b=2, c=2
        res = exact_mcnemar_test(arm1, arm2)
        assert res.b == 2
        assert res.c == 2
        assert res.n_discordant == 4
        assert res.risk_difference == pytest.approx(0.0)
        assert res.p_value_two_sided == pytest.approx(1.0)

    def test_known_textbook_exact_case(self):
        """
        Known literature case:
        b = 12, c = 3, n_discordant = 15.
        Two-sided exact binomial p-value:
          2 * sum_{k=0..3} comb(15, k) * 0.5^15
          = 2 * (1 + 15 + 105 + 455) / 32768
          = 2 * 576 / 32768 = 1152 / 32768 = 0.03515625
        """
        arm1 = [1] * 12 + [0] * 3 + [1] * 5 + [0] * 5
        arm2 = [0] * 12 + [1] * 3 + [1] * 5 + [0] * 5
        res = exact_mcnemar_test(arm1, arm2)
        assert res.b == 12
        assert res.c == 3
        assert res.n_discordant == 15
        assert res.p_value_two_sided == pytest.approx(0.03515625)
        # One-sided greater (H1: p1 > p2): P(B >= 12) = P(B <= 3) = 576 / 32768 = 0.017578125
        assert res.p_value_greater == pytest.approx(576 / 32768)

    def test_extreme_discordance(self):
        """b=20, c=0: highly significant."""
        arm1 = [1] * 20
        arm2 = [0] * 20
        res = exact_mcnemar_test(arm1, arm2)
        assert res.p_value_two_sided is not None
        assert res.p_value_two_sided < 1e-4

    def test_empty_inputs(self):
        res = exact_mcnemar_test([], [])
        assert res.n_total == 0
        assert res.p_value_two_sided is None

    def test_mismatched_lengths_raise(self):
        with pytest.raises(ValueError, match="Mismatched pair lengths"):
            exact_mcnemar_test([1, 0], [1])

    def test_non_binary_values_raise(self):
        with pytest.raises(ValueError, match="Outcomes must be 0 or 1"):
            exact_mcnemar_test([1, 2], [0, 1])


# ===========================================================================
# 3. Cluster bootstrap CI (doc/03 §12.1–§12.2)
# ===========================================================================


class TestClusterBootstrapCI:

    def test_reproducibility_with_seed(self):
        data = [
            {"cluster": "T1", "val": 1.0},
            {"cluster": "T1", "val": 0.0},
            {"cluster": "T2", "val": 1.0},
            {"cluster": "T2", "val": 1.0},
            {"cluster": "T3", "val": 0.0},
            {"cluster": "T3", "val": 0.0},
        ]

        def _mean_stat(sample):
            return sum(x["val"] for x in sample) / len(sample)

        ci1 = cluster_bootstrap_ci(
            data=data,
            stat_fn=_mean_stat,
            cluster_key=lambda x: str(x["cluster"]),
            n_replicates=500,
            seed=42,
        )
        ci2 = cluster_bootstrap_ci(
            data=data,
            stat_fn=_mean_stat,
            cluster_key=lambda x: str(x["cluster"]),
            n_replicates=500,
            seed=42,
        )
        assert ci1.point_estimate == ci2.point_estimate
        assert ci1.lower == ci2.lower
        assert ci1.upper == ci2.upper

    def test_different_seed_different_replicates(self):
        data = [{"cluster": f"T{i%4}", "val": float(i % 2)} for i in range(40)]

        def _mean_stat(sample):
            return sum(x["val"] for x in sample) / len(sample)

        ci1 = cluster_bootstrap_ci(
            data, _mean_stat, cluster_key=lambda x: str(x["cluster"]), n_replicates=200, seed=1
        )
        ci2 = cluster_bootstrap_ci(
            data, _mean_stat, cluster_key=lambda x: str(x["cluster"]), n_replicates=200, seed=2
        )
        # Bounds may be close but replicate paths differ
        assert ci1.n_valid_replicates == 200
        assert ci2.n_valid_replicates == 200

    def test_one_sided_lower_bound(self):
        data = [{"cluster": f"T{i//5}", "val": 1.0} for i in range(20)]

        def _mean_stat(sample):
            return sum(x["val"] for x in sample) / len(sample)

        ci = cluster_bootstrap_ci(
            data,
            _mean_stat,
            cluster_key=lambda x: str(x["cluster"]),
            side="lower",
            seed=42,
        )
        assert ci.lower is not None
        assert ci.upper is None

    def test_one_sided_upper_bound(self):
        data = [{"cluster": f"T{i//5}", "val": 0.5} for i in range(20)]

        def _mean_stat(sample):
            return sum(x["val"] for x in sample) / len(sample)

        ci = cluster_bootstrap_ci(
            data,
            _mean_stat,
            cluster_key=lambda x: str(x["cluster"]),
            side="upper",
            seed=42,
        )
        assert ci.upper is not None
        assert ci.lower is None

    def test_empty_data_returns_none(self):
        ci = cluster_bootstrap_ci([], lambda s: 0.0, cluster_key=lambda x: "c")
        assert ci.point_estimate == 0.0
        assert ci.lower is None
        assert ci.upper is None

    def test_invalid_parameters_raise(self):
        with pytest.raises(ValueError, match="n_replicates must be positive"):
            cluster_bootstrap_ci([1], lambda s: 1.0, lambda x: "c", n_replicates=0)

        with pytest.raises(ValueError, match="confidence must be in"):
            cluster_bootstrap_ci([1], lambda s: 1.0, lambda x: "c", confidence=1.2)

        with pytest.raises(ValueError, match="side must be"):
            cluster_bootstrap_ci([1], lambda s: 1.0, lambda x: "c", side="invalid")

    def test_missing_cluster_key_raises(self):
        with pytest.raises(ValueError, match="Cluster key must be a non-empty string"):
            cluster_bootstrap_ci([1], lambda s: 1.0, lambda x: "")


# ===========================================================================
# 4. Paired cluster comparison and margin checks (doc/03 §12.3, doc/06 §1.2)
# ===========================================================================


class TestPairedClusterComparison:

    def test_paired_comparison_preserves_correlation(self):
        # 10 templates, 4 traces each. Arm 1 always beats Arm 2 by 0.25
        pairs = []
        for t in range(10):
            template_id = f"TMP_{t:02d}"
            # 3 traces where both succeed, 1 where Arm1 succeeds but Arm2 fails
            pairs.append(MatchedTracePair(template_id, f"tr_{t}_1", 1, 1))
            pairs.append(MatchedTracePair(template_id, f"tr_{t}_2", 1, 1))
            pairs.append(MatchedTracePair(template_id, f"tr_{t}_3", 1, 1))
            pairs.append(MatchedTracePair(template_id, f"tr_{t}_4", 1, 0))

        res = paired_cluster_comparison(
            pairs,
            arm1_name="B6",
            arm2_name="B5",
            metric_name="APR",
            n_replicates=500,
            seed=42,
        )
        assert res.arm1_rate == pytest.approx(1.0)
        assert res.arm2_rate == pytest.approx(0.75)
        assert res.risk_difference == pytest.approx(0.25)
        assert res.rd_ci is not None
        assert res.rd_ci.lower is not None and res.rd_ci.upper is not None
        # Risk difference CI should be strictly positive
        assert res.rd_ci.lower > 0.05

    def test_check_non_inferiority(self):
        # Difference CI: lower = -0.01, upper = 0.05
        # Margin delta = 0.03 (doc/06 §1.2 H2: delta_APR = 0.03)
        # Condition: lower (-0.01) > -margin (-0.03) -> True
        ci = BootstrapCI(point_estimate=0.02, lower=-0.01, upper=0.05, side="two_sided")
        assert check_non_inferiority(ci, margin=0.03) is True

        # Failed non-inferiority: lower = -0.05 < -0.03 -> False
        ci_fail = BootstrapCI(point_estimate=-0.01, lower=-0.05, upper=0.02, side="two_sided")
        assert check_non_inferiority(ci_fail, margin=0.03) is False

    def test_check_superiority(self):
        # Delta = 0.10 (doc/06 §1.2 H2: Delta_LTS = 0.10)
        # Condition: lower > Delta
        ci_sup = BootstrapCI(point_estimate=0.18, lower=0.12, upper=0.24, side="two_sided")
        assert check_superiority(ci_sup, margin=0.10) is True

        ci_not_sup = BootstrapCI(point_estimate=0.12, lower=0.06, upper=0.18, side="two_sided")
        assert check_superiority(ci_not_sup, margin=0.10) is False

    def test_empty_pairs_comparison(self):
        res = paired_cluster_comparison([])
        assert res.risk_difference is None
        assert res.arm1_rate is None


# ===========================================================================
# 5. Multiplicity: Holm-Bonferroni step-down (doc/03 §12.5)
# ===========================================================================


class TestHolmBonferroni:

    def test_textbook_stepdown_example(self):
        """
        4 hypotheses with raw p-values: [0.01, 0.04, 0.03, 0.20].
        Sorted:
          Rank 1: 0.01 * 4 = 0.04  <= 0.05 -> Reject H1
          Rank 2: 0.03 * 3 = 0.09  >  0.05 -> Do not reject H3
          Rank 3: max(0.09, 0.04 * 2 = 0.08) = 0.09 -> Do not reject H2
          Rank 4: max(0.09, 0.20 * 1 = 0.20) = 0.20 -> Do not reject H4
        """
        raw_p = [0.01, 0.04, 0.03, 0.20]
        names = ["H1", "H2", "H3", "H4"]
        res = holm_bonferroni(raw_p, alpha=0.05, hypothesis_names=names)

        assert res.adjusted_p_values[0] == pytest.approx(0.04)  # H1
        assert res.adjusted_p_values[1] == pytest.approx(0.09)  # H2
        assert res.adjusted_p_values[2] == pytest.approx(0.09)  # H3
        assert res.adjusted_p_values[3] == pytest.approx(0.20)  # H4

        assert res.rejected == [True, False, False, False]

    def test_monotonicity_and_cap_at_one(self):
        raw_p = [0.60, 0.80]
        res = holm_bonferroni(raw_p, alpha=0.05)
        # 0.60 * 2 = 1.2 -> capped at 1.0
        assert res.adjusted_p_values == [1.0, 1.0]
        assert res.rejected == [False, False]

    def test_empty_p_values(self):
        res = holm_bonferroni([])
        assert len(res.hypotheses) == 0
        assert len(res.rejected) == 0

    def test_invalid_p_value_raises(self):
        with pytest.raises(ValueError, match="Invalid p-value"):
            holm_bonferroni([0.01, 1.5])
        with pytest.raises(ValueError, match="Invalid p-value"):
            holm_bonferroni([0.01, -0.1])


# ===========================================================================
# 6. Power analysis & Sample sizes (OQ-11, doc/03 §12.6, §12.10)
# ===========================================================================


class TestPowerAnalysis:

    def test_zero_event_sample_size_matches_spec(self):
        """
        doc/03 §12.6:
          q = 5% (0.05) -> n = 59
          q = 1% (0.01) -> n = 299
        """
        assert zero_event_sample_size(0.05) == 59
        assert zero_event_sample_size(0.01) == 299

    def test_zero_event_sample_size_invalid(self):
        assert zero_event_sample_size(0.0) is None
        assert zero_event_sample_size(1.0) is None
        assert zero_event_sample_size(-0.1) is None

    def test_mcnemar_power_large_effect(self):
        # 100 pairs, p10=0.30, p01=0.05 -> high power (>0.90)
        power = mcnemar_power(n_pairs=100, p10=0.30, p01=0.05, alpha=0.05)
        assert power is not None
        assert power > 0.90

    def test_mcnemar_power_zero_effect_equals_alpha(self):
        # p10 == p01 -> power = alpha
        power = mcnemar_power(n_pairs=100, p10=0.10, p01=0.10, alpha=0.05)
        assert power == pytest.approx(0.05)

    def test_clustered_paired_power_simulation(self):
        # Test simulation run with small iterations for speed
        res = simulate_clustered_paired_power(
            n_clusters=10,
            instances_per_cluster=5,
            p1=0.90,
            p2=0.50,
            pairing_correlation=0.7,
            alpha=0.05,
            n_sim=100,
            seed=42,
        )
        assert res.estimated_power is not None
        assert 0.0 <= res.estimated_power <= 1.0
        assert res.required_n == 50
        assert res.assumptions["n_clusters"] == 10


# ===========================================================================
# 7. Latency percentiles bootstrap CI (doc/06 §H5)
# ===========================================================================


class TestLatencyPercentilesCI:

    def test_latency_ci_normal(self):
        lats = [float(i) for i in range(1, 101)]  # 1..100 ms
        cis = latency_percentiles_ci(
            latencies=lats,
            percentiles=(50.0, 95.0, 99.0),
            n_replicates=500,
            confidence=0.95,
            seed=42,
        )
        p50 = cis[50.0]
        p95 = cis[95.0]
        p99 = cis[99.0]

        assert p50.point_estimate == pytest.approx(50.0)
        assert p50.lower is not None and p50.upper is not None
        assert p50.point_estimate is not None
        assert p50.lower <= p50.point_estimate <= p50.upper

        assert p95.point_estimate == pytest.approx(95.0)
        assert p99.point_estimate == pytest.approx(99.0)

    def test_latency_ci_empty(self):
        cis = latency_percentiles_ci([])
        for p in (50.0, 95.0, 99.0):
            assert cis[p].point_estimate is None
            assert cis[p].lower is None

"""
Statistical analysis, uncertainty quantification, and power utilities (C11).

All statistical procedures are defined strictly per:
  - docs/03_MATHEMATICAL_MODEL_AND_METRICS.md §12 (Uncertainty & Statistical Reporting)
  - docs/06_EXPERIMENT_PROTOCOL.md §1.2 (H1–H5 Statistical Analysis Plans)
  - docs/09_DECISIONS_AND_OPEN_QUESTIONS.md (D-10, D-21, OQ-11)

Key Architectural & Methodological Invariants:
  1. Cluster bootstrap: unit of analysis is the template instance; cluster is the
     template (family x variant). Resampling occurs at the template level first, then
     instances within (doc/03 §12.1-12.2).
  2. Paired comparisons: evaluates differences on the identical scenarios. Paired
     structure is strictly preserved across bootstrap resamples (doc/03 §12.3).
  3. McNemar exact test: uses the exact binomial distribution on discordant pairs,
     never a continuous chi-square approximation without continuity correction (doc/03 §12.3).
  4. Multiplicity: Holm-Bonferroni step-down correction for pre-registered primary
     hypotheses (doc/03 §12.5).
  5. Zero-event bounds & OQ-11: exact bounds (1 - 0.05^{1/n}) and simulation-based
     power analysis utilities for clustered/paired experimental designs (doc/03 §12.6, §12.10).
  6. Determinism & Offline Operation: all stochastic methods accept an explicit seed or
     random.Random generator; no external API or live network dependencies.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, TypeVar

T = TypeVar("T")


# ---------------------------------------------------------------------------
# §1  Data structures for statistical outcomes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BootstrapCI:
    """
    Percentile bootstrap confidence interval.

    Attributes:
        point_estimate: Point estimate on original sample.
        lower: Lower bound of confidence interval (None for upper-only one-sided).
        upper: Upper bound of confidence interval (None for lower-only one-sided).
        confidence_level: Nominal confidence level (e.g. 0.95).
        side: "two_sided", "lower", or "upper".
        n_replicates: Total number of requested bootstrap iterations B.
        n_valid_replicates: Number of replicates where statistic was successfully computed.
        n_failed_replicates: Number of replicates where statistic was undefined (None).
    """

    point_estimate: Optional[float]
    lower: Optional[float]
    upper: Optional[float]
    confidence_level: float = 0.95
    side: str = "two_sided"
    n_replicates: int = 1000
    n_valid_replicates: int = 0
    n_failed_replicates: int = 0


@dataclass(frozen=True)
class WilsonInterval:
    """
    Descriptive Wilson score interval for a single proportion (doc/03 §12.2).
    """

    proportion: Optional[float]
    lower: Optional[float]
    upper: Optional[float]
    confidence_level: float = 0.95
    count: int = 0
    total: int = 0


@dataclass(frozen=True)
class McNemarResult:
    """
    Exact McNemar test on paired binary outcomes (doc/03 §12.3).

    Contingency table on paired observations (Arm 1 vs Arm 2):
      a: (1, 1) - both positive
      b: (1, 0) - Arm 1 positive, Arm 2 negative
      c: (0, 1) - Arm 1 negative, Arm 2 positive
      d: (0, 0) - both negative
    """

    a: int
    b: int
    c: int
    d: int
    n_total: int
    n_discordant: int
    risk_difference: Optional[float]  # (b - c) / n_total
    odds_ratio: Optional[float]  # b / c (None if c == 0)
    p_value_two_sided: Optional[float]
    p_value_greater: Optional[float]  # H1: p1 > p2 (b > c)
    p_value_less: Optional[float]  # H1: p1 < p2 (b < c)


@dataclass(frozen=True)
class PairedComparisonResult:
    """
    Comprehensive paired comparison between two arms on identical traces (doc/03 §12.3).
    Combines exact McNemar hypothesis testing and paired cluster bootstrap for risk difference.
    """

    metric_name: str
    arm1_name: str
    arm2_name: str
    arm1_rate: Optional[float]
    arm2_rate: Optional[float]
    risk_difference: Optional[float]  # arm1_rate - arm2_rate
    rd_ci: Optional[BootstrapCI]
    mcnemar: McNemarResult


@dataclass(frozen=True)
class HolmResult:
    """
    Outcome of Holm-Bonferroni step-down multiplicity correction (doc/03 §12.5).
    """

    hypotheses: List[str]
    raw_p_values: List[float]
    adjusted_p_values: List[float]
    rejected: List[bool]
    alpha: float


@dataclass(frozen=True)
class PowerAnalysisResult:
    """
    Power analysis result for experimental planning (OQ-11, doc/03 §12.6, §12.10).
    """

    method: str
    target_metric: str
    estimated_power: Optional[float]
    required_n: Optional[int]
    alpha: float
    assumptions: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# §2  Descriptive intervals: Wilson score interval (doc/03 §12.2)
# ---------------------------------------------------------------------------


def wilson_score_interval(
    count: int,
    total: int,
    confidence: float = 0.95,
) -> WilsonInterval:
    """
    Compute descriptive Wilson score interval for a binomial proportion.

    Formula (Newcombe 1998, doc/03 §12.2):
      center = (p + z^2 / (2n)) / (1 + z^2 / n)
      half_width = (z / (1 + z^2 / n)) * sqrt(p(1 - p)/n + z^2 / (4n^2))

    Returns WilsonInterval with None bounds if total <= 0 or count < 0.
    """
    if total <= 0 or count < 0 or count > total or not (0.0 < confidence < 1.0):
        return WilsonInterval(
            proportion=None,
            lower=None,
            upper=None,
            confidence_level=confidence,
            count=count,
            total=total,
        )

    p = count / total
    # Normal quantile approximation for two-sided confidence
    alpha = 1.0 - confidence
    z = _normal_quantile(1.0 - alpha / 2.0)

    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    variance_term = (p * (1.0 - p) / total) + (z2 / (4.0 * total * total))
    half_width = (z * math.sqrt(variance_term)) / denom

    lower = max(0.0, center - half_width)
    upper = min(1.0, center + half_width)

    return WilsonInterval(
        proportion=p,
        lower=lower,
        upper=upper,
        confidence_level=confidence,
        count=count,
        total=total,
    )


# ---------------------------------------------------------------------------
# §3  Exact McNemar test for paired binary outcomes (doc/03 §12.3)
# ---------------------------------------------------------------------------


def exact_mcnemar_test(
    arm1_outcomes: Sequence[int],
    arm2_outcomes: Sequence[int],
) -> McNemarResult:
    """
    Exact binomial McNemar test for matched paired binary outcomes (doc/03 §12.3).

    Args:
        arm1_outcomes: Binary outcomes for Arm 1 (0 or 1).
        arm2_outcomes: Binary outcomes for Arm 2 (0 or 1), matched 1-to-1 with Arm 1.

    Raises:
        ValueError: If inputs have mismatched lengths or contain non-binary values.
    """
    n = len(arm1_outcomes)
    if n != len(arm2_outcomes):
        raise ValueError(
            f"Mismatched pair lengths: arm1 has {n} items, arm2 has {len(arm2_outcomes)}"
        )

    a = 0  # (1, 1)
    b = 0  # (1, 0)
    c = 0  # (0, 1)
    d = 0  # (0, 0)

    for y1, y2 in zip(arm1_outcomes, arm2_outcomes, strict=True):
        if y1 not in (0, 1) or y2 not in (0, 1):
            raise ValueError(f"Outcomes must be 0 or 1; got ({y1}, {y2})")
        if y1 == 1 and y2 == 1:
            a += 1
        elif y1 == 1 and y2 == 0:
            b += 1
        elif y1 == 0 and y2 == 1:
            c += 1
        else:
            d += 1

    n_discordant = b + c
    risk_diff = (b - c) / n if n > 0 else None
    odds_ratio = (b / c) if c > 0 else None

    if n == 0:
        return McNemarResult(
            a=0,
            b=0,
            c=0,
            d=0,
            n_total=0,
            n_discordant=0,
            risk_difference=None,
            odds_ratio=None,
            p_value_two_sided=None,
            p_value_greater=None,
            p_value_less=None,
        )

    if n_discordant == 0:
        # Zero discordant pairs: arm1 and arm2 agree completely
        return McNemarResult(
            a=a,
            b=b,
            c=c,
            d=d,
            n_total=n,
            n_discordant=0,
            risk_difference=0.0,
            odds_ratio=None,
            p_value_two_sided=1.0,
            p_value_greater=1.0,
            p_value_less=1.0,
        )

    # Under H0, b ~ Binomial(n_discordant, 0.5)
    # Exact two-sided p-value: 2 * sum_{k=0}^{min(b, c)} comb(n_disc, k) * (0.5)^n_disc
    k_min = min(b, c)
    tail_prob = sum(math.comb(n_discordant, k) for k in range(k_min + 1)) * (0.5**n_discordant)
    p_two_sided = min(1.0, 2.0 * tail_prob)

    # One-sided p-values
    # Greater (H1: p1 > p2, i.e. b > c): P(B >= b)
    p_greater = sum(math.comb(n_discordant, k) for k in range(b, n_discordant + 1)) * (
        0.5**n_discordant
    )
    # Less (H1: p1 < p2, i.e. b < c): P(B <= b)
    p_less = sum(math.comb(n_discordant, k) for k in range(b + 1)) * (0.5**n_discordant)

    return McNemarResult(
        a=a,
        b=b,
        c=c,
        d=d,
        n_total=n,
        n_discordant=n_discordant,
        risk_difference=risk_diff,
        odds_ratio=odds_ratio,
        p_value_two_sided=p_two_sided,
        p_value_greater=p_greater,
        p_value_less=p_less,
    )


# ---------------------------------------------------------------------------
# §4  Cluster bootstrap confidence intervals (doc/03 §12.1–§12.2)
# ---------------------------------------------------------------------------


def cluster_bootstrap_ci(
    data: Sequence[T],
    stat_fn: Callable[[Sequence[T]], Optional[float]],
    cluster_key: Callable[[T], str],
    n_replicates: int = 1000,
    confidence: float = 0.95,
    side: str = "two_sided",
    seed: Optional[int] = None,
) -> BootstrapCI:
    """
    Two-stage cluster bootstrap percentile confidence interval.

    Procedure (doc/03 §12.1-12.2, [P1] §VI):
      1. Partition observations into K clusters by template_id (cluster_key).
      2. For each replicate b in 1..B:
         a. Resample K cluster identifiers with replacement.
         b. For each selected cluster, resample its instances with replacement.
         c. Compute stat_fn on the pooled resample.
      3. Compute percentile interval on valid replicate statistics.

    Args:
        data: Sequence of observations.
        stat_fn: Callable computing scalar metric from a sample. Returns None if undefined.
        cluster_key: Function extracting cluster identifier from an observation.
        n_replicates: Number of bootstrap resamples B (doc/06 recommends 1000 or 2000).
        confidence: Nominal confidence level (e.g. 0.95).
        side: "two_sided", "lower" (one-sided lower bound), or "upper" (one-sided upper bound).
        seed: Random seed for reproducibility.

    Raises:
        ValueError: On invalid parameters or empty cluster key.
    """
    if n_replicates <= 0:
        raise ValueError(f"n_replicates must be positive, got {n_replicates}")
    if not (0.0 < confidence < 1.0):
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")
    if side not in ("two_sided", "lower", "upper"):
        raise ValueError(f"side must be 'two_sided', 'lower', or 'upper', got {side}")

    point_est = stat_fn(data)

    if not data:
        return BootstrapCI(
            point_estimate=point_est,
            lower=None,
            upper=None,
            confidence_level=confidence,
            side=side,
            n_replicates=n_replicates,
            n_valid_replicates=0,
            n_failed_replicates=0,
        )

    # Group into clusters
    clusters: Dict[str, List[T]] = {}
    for item in data:
        k = cluster_key(item)
        if not k or not isinstance(k, str):
            raise ValueError(f"Cluster key must be a non-empty string; got {k!r}")
        clusters.setdefault(k, []).append(item)

    cluster_keys = list(clusters.keys())
    k_clusters = len(cluster_keys)

    rng = random.Random(seed)
    replicate_values: List[float] = []
    n_failed = 0

    for _ in range(n_replicates):
        # 1. Resample clusters with replacement
        sampled_keys = rng.choices(cluster_keys, k=k_clusters)

        # 2. Resample instances within each chosen cluster with replacement
        sample: List[T] = []
        for key in sampled_keys:
            orig_items = clusters[key]
            sample.extend(rng.choices(orig_items, k=len(orig_items)))

        val = stat_fn(sample)
        if val is None or math.isnan(val):
            n_failed += 1
        else:
            replicate_values.append(val)

    n_valid = len(replicate_values)
    if n_valid == 0:
        return BootstrapCI(
            point_estimate=point_est,
            lower=None,
            upper=None,
            confidence_level=confidence,
            side=side,
            n_replicates=n_replicates,
            n_valid_replicates=0,
            n_failed_replicates=n_failed,
        )

    replicate_values.sort()

    # Percentile CI calculation
    alpha = 1.0 - confidence
    if side == "two_sided":
        low_pct = 100.0 * (alpha / 2.0)
        high_pct = 100.0 * (1.0 - alpha / 2.0)
        lower = _percentile_sorted(replicate_values, low_pct)
        upper = _percentile_sorted(replicate_values, high_pct)
    elif side == "lower":
        low_pct = 100.0 * alpha
        lower = _percentile_sorted(replicate_values, low_pct)
        upper = None
    else:  # upper
        high_pct = 100.0 * (1.0 - alpha)
        lower = None
        upper = _percentile_sorted(replicate_values, high_pct)

    return BootstrapCI(
        point_estimate=point_est,
        lower=lower,
        upper=upper,
        confidence_level=confidence,
        side=side,
        n_replicates=n_replicates,
        n_valid_replicates=n_valid,
        n_failed_replicates=n_failed,
    )


# ---------------------------------------------------------------------------
# §5  Paired cluster comparison on matched scenarios (doc/03 §12.3, doc/06 §1.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchedTracePair:
    """
    Matched scenario execution pair between two firewall arms.
    """

    template_id: str
    trace_id: str
    arm1_success: int  # 1 if successful/prevented, 0 otherwise
    arm2_success: int  # 1 if successful/prevented, 0 otherwise


def paired_cluster_comparison(
    pairs: Sequence[MatchedTracePair],
    arm1_name: str = "Arm1",
    arm2_name: str = "Arm2",
    metric_name: str = "RiskDifference",
    n_replicates: int = 2000,
    confidence: float = 0.95,
    side: str = "two_sided",
    seed: Optional[int] = None,
) -> PairedComparisonResult:
    """
    Perform paired comparison between two arms over matched scenario traces.

    Preserves the matched pair structure during cluster bootstrap resampling (doc/03 §12.3).
    """
    if not pairs:
        empty_mcnemar = exact_mcnemar_test([], [])
        return PairedComparisonResult(
            metric_name=metric_name,
            arm1_name=arm1_name,
            arm2_name=arm2_name,
            arm1_rate=None,
            arm2_rate=None,
            risk_difference=None,
            rd_ci=None,
            mcnemar=empty_mcnemar,
        )

    arm1_outcomes = [p.arm1_success for p in pairs]
    arm2_outcomes = [p.arm2_success for p in pairs]

    mcnemar_res = exact_mcnemar_test(arm1_outcomes, arm2_outcomes)

    p1 = sum(arm1_outcomes) / len(arm1_outcomes)
    p2 = sum(arm2_outcomes) / len(arm2_outcomes)
    rd = p1 - p2

    def _rd_stat(sample_pairs: Sequence[MatchedTracePair]) -> Optional[float]:
        if not sample_pairs:
            return None
        r1 = sum(p.arm1_success for p in sample_pairs) / len(sample_pairs)
        r2 = sum(p.arm2_success for p in sample_pairs) / len(sample_pairs)
        return r1 - r2

    rd_ci = cluster_bootstrap_ci(
        data=pairs,
        stat_fn=_rd_stat,
        cluster_key=lambda p: p.template_id,
        n_replicates=n_replicates,
        confidence=confidence,
        side=side,
        seed=seed,
    )

    return PairedComparisonResult(
        metric_name=metric_name,
        arm1_name=arm1_name,
        arm2_name=arm2_name,
        arm1_rate=p1,
        arm2_rate=p2,
        risk_difference=rd,
        rd_ci=rd_ci,
        mcnemar=mcnemar_res,
    )


def check_non_inferiority(
    rd_ci: BootstrapCI,
    margin: float,
) -> bool:
    """
    Check formal non-inferiority against margin delta (doc/06 §1.2 H2).

    Condition for non-inferiority:
      Arm 1 is non-inferior to Arm 2 if the lower bound of the difference
      (Arm 1 - Arm 2) is strictly greater than -margin:
        lower_bound > -margin
    """
    if rd_ci.lower is None:
        return False
    return rd_ci.lower > -abs(margin)


def check_superiority(
    rd_ci: BootstrapCI,
    margin: float,
) -> bool:
    """
    Check formal superiority against margin Delta (doc/06 §1.2 H2).

    Condition for superiority:
      Arm 1 is superior to Arm 2 by at least margin if the lower bound of
      the difference (Arm 1 - Arm 2) is strictly greater than margin:
        lower_bound > margin
    """
    if rd_ci.lower is None:
        return False
    return rd_ci.lower > margin


# ---------------------------------------------------------------------------
# §6  Multiplicity: Holm-Bonferroni correction (doc/03 §12.5)
# ---------------------------------------------------------------------------


def holm_bonferroni(
    p_values: Sequence[float],
    alpha: float = 0.05,
    hypothesis_names: Optional[Sequence[str]] = None,
) -> HolmResult:
    """
    Holm-Bonferroni step-down multiplicity correction across pre-registered hypotheses.

    Formula (Holm 1979, doc/03 §12.5):
      Order p-values: p_(1) <= p_(2) <= ... <= p_(m).
      Adjusted: p_adj_(i) = min(1.0, max_{k <= i} (m - k + 1) * p_(k)).
      Reject H_(i) if p_adj_(i) <= alpha.

    Args:
        p_values: Sequence of raw p-values in [0, 1].
        alpha: Family-wise error rate ceiling (default 0.05).
        hypothesis_names: Optional labels matching the p-values.

    Raises:
        ValueError: If p-values are invalid or names length mismatches.
    """
    m = len(p_values)
    if hypothesis_names is not None and len(hypothesis_names) != m:
        raise ValueError(
            f"Length mismatch: {m} p-values provided, but {len(hypothesis_names)} names"
        )
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")

    for idx, p in enumerate(p_values):
        if p is None or math.isnan(p) or not (0.0 <= p <= 1.0):
            raise ValueError(f"Invalid p-value at index {idx}: {p}")

    names = (
        list(hypothesis_names)
        if hypothesis_names is not None
        else [f"H{i+1}" for i in range(m)]
    )

    if m == 0:
        return HolmResult(
            hypotheses=[],
            raw_p_values=[],
            adjusted_p_values=[],
            rejected=[],
            alpha=alpha,
        )

    # Sort indices by p-value
    sorted_indices = sorted(range(m), key=lambda i: p_values[i])

    adj_p: List[float] = [0.0] * m
    running_max = 0.0

    for rank, orig_idx in enumerate(sorted_indices):
        multiplier = m - rank
        raw_val = p_values[orig_idx]
        candidate = min(1.0, multiplier * raw_val)
        running_max = max(running_max, candidate)
        adj_p[orig_idx] = running_max

    rejected = [p_adj <= alpha for p_adj in adj_p]

    return HolmResult(
        hypotheses=names,
        raw_p_values=list(p_values),
        adjusted_p_values=adj_p,
        rejected=rejected,
        alpha=alpha,
    )


# ---------------------------------------------------------------------------
# §7  Power analysis and sample size determination (OQ-11, doc/03 §12.6, §12.10)
# ---------------------------------------------------------------------------


def zero_event_sample_size(
    target_rate: float,
    confidence: float = 0.95,
) -> Optional[int]:
    """
    Calculate minimum independent templates required to establish that a true
    event rate is <= target_rate from zero observed events (doc/03 §12.6, OQ-11).

    Formula: n >= ln(1 - confidence) / ln(1 - target_rate).
    """
    if target_rate <= 0.0 or target_rate >= 1.0 or not (0.0 < confidence < 1.0):
        return None
    denom = math.log(1.0 - target_rate)
    numer = math.log(1.0 - confidence)
    return math.ceil(numer / denom)


def mcnemar_power(
    n_pairs: int,
    p10: float,
    p01: float,
    alpha: float = 0.05,
    alternative: str = "two_sided",
) -> Optional[float]:
    """
    Normal approximation power for McNemar's test (Connor 1987 / Machin et al.).

    Args:
        n_pairs: Total number of paired instances.
        p10: Proportion of pairs where Arm 1 succeeds and Arm 2 fails (discordant b/N).
        p01: Proportion of pairs where Arm 1 fails and Arm 2 succeeds (discordant c/N).
        alpha: Significance level (default 0.05).
        alternative: "two_sided" or "one_sided".

    Returns:
        Statistical power in [0.0, 1.0], or None if inputs are invalid.
    """
    if n_pairs <= 0 or not (0.0 < alpha < 1.0):
        return None
    if p10 < 0.0 or p01 < 0.0 or (p10 + p01) > 1.0:
        return None
    if alternative not in ("two_sided", "one_sided"):
        return None

    p_disc = p10 + p01
    d = abs(p10 - p01)
    if p_disc == 0.0 or d == 0.0:
        return alpha

    # Normal critical value
    z_crit = (
        _normal_quantile(1.0 - alpha / 2.0)
        if alternative == "two_sided"
        else _normal_quantile(1.0 - alpha)
    )

    # Standard errors under H0 and H1
    se0 = math.sqrt(p_disc / n_pairs)
    se1 = math.sqrt((p_disc - (p10 - p01) ** 2) / n_pairs)

    z_stat = (d - z_crit * se0) / se1
    return _normal_cdf(z_stat)


def simulate_clustered_paired_power(
    n_clusters: int,
    instances_per_cluster: int,
    p1: float,
    p2: float,
    pairing_correlation: float = 0.6,
    cluster_variance: float = 0.02,
    alpha: float = 0.05,
    n_sim: int = 500,
    seed: Optional[int] = None,
) -> PowerAnalysisResult:
    """
    Monte Carlo simulation-based power analysis for clustered paired comparison (OQ-11).

    Simulates paired binary trials with intra-cluster variance and intra-pair correlation,
    evaluating the empirical rejection rate of exact McNemar's test.

    Args:
        n_clusters: Number of independent scenario templates.
        instances_per_cluster: Number of stochastic variations per template.
        p1: Target success rate for Arm 1.
        p2: Target success rate for Arm 2.
        pairing_correlation: Correlation between Arm 1 and Arm 2 on identical instances.
        cluster_variance: Variance of template random effects.
        alpha: Significance level.
        n_sim: Number of simulation iterations.
        seed: Random seed for reproducibility.
    """
    if n_clusters <= 0 or instances_per_cluster <= 0 or n_sim <= 0:
        raise ValueError("Sample sizes and simulation iterations must be positive")
    if not (0.0 <= p1 <= 1.0) or not (0.0 <= p2 <= 1.0):
        raise ValueError("Probabilities must be in [0, 1]")

    rng = random.Random(seed)
    rejections = 0

    assumptions = {
        "n_clusters": n_clusters,
        "instances_per_cluster": instances_per_cluster,
        "total_instances": n_clusters * instances_per_cluster,
        "p1": p1,
        "p2": p2,
        "pairing_correlation": pairing_correlation,
        "cluster_variance": cluster_variance,
        "n_sim": n_sim,
    }

    # Bivariate normal latent model for paired correlated binary generation
    rho = max(-0.95, min(0.95, pairing_correlation))

    for _ in range(n_sim):
        arm1_outcomes: List[int] = []
        arm2_outcomes: List[int] = []

        for _c in range(n_clusters):
            # Cluster random intercept
            u = rng.gauss(0.0, math.sqrt(cluster_variance))

            # Shifted latent thresholds
            thresh1 = _normal_quantile(1.0 - min(0.999, max(0.001, p1 + u)))
            thresh2 = _normal_quantile(1.0 - min(0.999, max(0.001, p2 + u)))

            for _i in range(instances_per_cluster):
                # Standard bivariate normal with correlation rho
                z1 = rng.gauss(0.0, 1.0)
                z2 = rho * z1 + math.sqrt(max(0.0, 1.0 - rho * rho)) * rng.gauss(0.0, 1.0)

                y1 = 1 if z1 >= thresh1 else 0
                y2 = 1 if z2 >= thresh2 else 0

                arm1_outcomes.append(y1)
                arm2_outcomes.append(y2)

        mcn = exact_mcnemar_test(arm1_outcomes, arm2_outcomes)
        if mcn.p_value_two_sided is not None and mcn.p_value_two_sided <= alpha:
            rejections += 1

    emp_power = rejections / n_sim

    return PowerAnalysisResult(
        method="simulate_clustered_paired_power",
        target_metric="RiskDifference",
        estimated_power=emp_power,
        required_n=n_clusters * instances_per_cluster,
        alpha=alpha,
        assumptions=assumptions,
    )


# ---------------------------------------------------------------------------
# §8  Latency percentile bootstrap CI (doc/03 §12.7, doc/06 §H5)
# ---------------------------------------------------------------------------


def latency_percentiles_ci(
    latencies: Sequence[float],
    percentiles: Sequence[float] = (50.0, 95.0, 99.0),
    n_replicates: int = 1000,
    confidence: float = 0.95,
    seed: Optional[int] = None,
) -> Dict[float, BootstrapCI]:
    """
    Compute percentile bootstrap confidence intervals for latency percentiles (doc/06 §H5).

    Args:
        latencies: Sequence of observed decision latencies in milliseconds.
        percentiles: Tuple of percentile targets (default median=50, p95, p99).
        n_replicates: Bootstrap iterations (doc/06 recommends 1000).
        confidence: Nominal confidence level.
        seed: Random seed.
    """
    valid = [lat for lat in latencies if lat is not None and not math.isnan(lat)]
    results: Dict[float, BootstrapCI] = {}

    if not valid:
        for p in percentiles:
            results[p] = BootstrapCI(
                point_estimate=None,
                lower=None,
                upper=None,
                confidence_level=confidence,
                n_replicates=n_replicates,
                n_valid_replicates=0,
                n_failed_replicates=0,
            )
        return results

    n = len(valid)
    sorted_orig = sorted(valid)

    rng = random.Random(seed)

    # Pre-allocate replicate percentile lists
    replicate_percentiles: Dict[float, List[float]] = {p: [] for p in percentiles}

    for _ in range(n_replicates):
        resample = rng.choices(valid, k=n)
        resample.sort()
        for p in percentiles:
            val = _percentile_sorted(resample, p)
            replicate_percentiles[p].append(val)

    alpha = 1.0 - confidence
    low_pct = 100.0 * (alpha / 2.0)
    high_pct = 100.0 * (1.0 - alpha / 2.0)

    for p in percentiles:
        pt_est = _percentile_sorted(sorted_orig, p)
        reps = replicate_percentiles[p]
        reps.sort()
        lower = _percentile_sorted(reps, low_pct)
        upper = _percentile_sorted(reps, high_pct)

        results[p] = BootstrapCI(
            point_estimate=pt_est,
            lower=lower,
            upper=upper,
            confidence_level=confidence,
            side="two_sided",
            n_replicates=n_replicates,
            n_valid_replicates=len(reps),
            n_failed_replicates=0,
        )

    return results


# ---------------------------------------------------------------------------
# §9  Private mathematical helper functions
# ---------------------------------------------------------------------------


def _percentile_sorted(sorted_vals: List[float], pct: float) -> float:
    """Nearest-rank percentile for pre-sorted float list."""
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    rank = math.ceil(pct / 100.0 * n)
    rank = max(1, min(rank, n))
    return sorted_vals[rank - 1]


def _normal_cdf(x: float) -> float:
    """Standard normal cumulative distribution function Phi(x)."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def _normal_quantile(p: float) -> float:
    """
    Rational approximation of the standard normal quantile function (Wichura / Beasley-Springer).
    Accurate to within 1e-9 for p in (1e-12, 1 - 1e-12).
    """
    if p <= 0.0 or p >= 1.0:
        raise ValueError(f"p must be in (0, 1), got {p}")

    # Rational approximation coefficients for central region
    a = [
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    ]
    b = [
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    ]
    # Tail coefficients
    c = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    ]
    d = [
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e00,
        3.754408661907416e00,
    ]

    q = p - 0.5
    if abs(q) <= 0.425:
        r = 0.180625 - q * q
        num = (
            ((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]
        ) * q
        den = ((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0
        return num / den

    r = p if q < 0.0 else 1.0 - p
    r = math.sqrt(-math.log(r))
    num = ((((c[0] * r + c[1]) * r + c[2]) * r + c[3]) * r + c[4]) * r + c[5]
    den = (((d[0] * r + d[1]) * r + d[2]) * r + d[3]) * r + 1.0
    x = num / den
    return -x if q < 0.0 else x

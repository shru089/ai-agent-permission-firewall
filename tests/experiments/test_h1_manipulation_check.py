"""
Tests for H1 Manipulation-Check Acceptance Validator and DEV Handoff.

Verifies:
1. Validator uses exclusively the authoritative criteria from docs/06, docs/03, and PREREG-001.
2. J is not hardcoded (dynamically computed from decisions).
3. Action-D invariance is not hardcoded (dynamically verified on critical actions).
4. Confidence interval is computed via cluster bootstrap over pairs.
5. B3 and B4 are distinct, separate evaluation paths.
6. The protocol artifact (protocol.md) contains no evaluation results or PASS/FAIL status.
7. Real dataset schema and pair linkage (twin_trace_id) correctly pass all checks.
"""

from pathlib import Path
from typing import Any

from experiments.datasets.dev.h1_impl import (
    B3CheckResult,
    B4CheckResult,
    H1Status,
    cluster_bootstrap_b4,
    compute_youden_j,
    evaluate_b3_determinism,
    evaluate_b4_stochastic,
    run_h1_check,
    verify_action_d_invariance,
)
from experiments.validation.h1_manipulation_check import (
    H1ManipulationCheckValidator,
)


def test_h1_authoritative_criterion_source_and_quote() -> None:
    """Verifies that validator records exact source file, line/section, and quoted criterion."""
    validator = H1ManipulationCheckValidator()
    assert validator.criterion_metadata["protocol_file"] == "docs/06_EXPERIMENT_PROTOCOL.md"
    assert "§2.1" in validator.criterion_metadata["protocol_section"]
    assert "§2.2" in validator.criterion_metadata["protocol_section"]
    assert "J = 0 exactly" in validator.criterion_metadata["b3_quoted_criterion"]
    assert "absolute J <= 0.03" in validator.criterion_metadata["b4_quoted_criterion"]
    assert (
        "95% cluster-bootstrap confidence interval including 0"
        in validator.criterion_metadata["b4_quoted_criterion"]
    )


def test_h1_protocol_artifact_contains_no_results() -> None:
    """
    Verifies that experiments/datasets/dev/protocol.md contains specifications only
    and does NOT contain computed evaluation results or final PASS/FAIL status.
    """
    protocol_path = Path("experiments/datasets/dev/protocol.md")
    assert protocol_path.exists(), "experiments/datasets/dev/protocol.md does not exist!"

    content = protocol_path.read_text(encoding="utf-8")

    # Authoritative sections must be present
    assert "docs/06_EXPERIMENT_PROTOCOL.md" in content
    assert "docs/03_MATHEMATICAL_MODEL_AND_METRICS.md" in content
    assert "docs/prereg/PREREG-001_DRAFT.md" in content
    assert "Youden's Index" in content or "Youden's" in content
    assert "Action-D Invariance" in content
    assert "Cluster-Bootstrap" in content or "cluster-bootstrap" in content

    # Must NOT contain evaluation outcomes or PASS/FAIL determination
    assert "## Status: PASS" not in content
    assert "## Status: FAIL" not in content
    assert "**Result:** **`PASS`**" not in content
    assert "True Positives ($TP$): 8" not in content
    assert "Computed Youden's $J$: 0.0000" not in content


def test_h1_j_not_hardcoded() -> None:
    """
    Verifies that Youden's J is dynamically computed from decisions, not hardcoded.
    If an evaluator produces asymmetric decisions (e.g. leaking ground truth),
    J must reflect the exact empirical difference.
    """
    # 1. Leaky evaluator: flags all attacks (TP=8), flags no benigns (FP=0) -> J = 1.0 - 0.0 = 1.0
    decisions_leaky = [(1, 1)] * 8 + [(0, 0)] * 8
    j_leaky, rec_leaky, fpr_leaky, _ = compute_youden_j(decisions_leaky)
    assert j_leaky == 1.0
    assert rec_leaky == 1.0
    assert fpr_leaky == 0.0

    # 2. Inverted evaluator: flags all benigns (FP=8), flags no attacks (TP=0) -> J = -1.0
    decisions_inv = [(1, 0)] * 8 + [(0, 1)] * 8
    j_inv, rec_inv, fpr_inv, _ = compute_youden_j(decisions_inv)
    assert j_inv == -1.0
    assert rec_inv == 0.0
    assert fpr_inv == 1.0

    # 3. Identical flag behavior (action-only on identical action): TP=8, FP=8 -> J = 0.0
    decisions_sym = [(1, 1)] * 8 + [(0, 1)] * 8
    j_sym, rec_sym, fpr_sym, _ = compute_youden_j(decisions_sym)
    assert j_sym == 0.0
    assert rec_sym == 1.0
    assert fpr_sym == 1.0


def test_h1_action_d_invariance_verification_not_hardcoded() -> None:
    """
    Verifies that Action-D invariance is genuinely verified by comparing
    critical action tool and arguments byte-for-byte, and is NOT hardcoded to True.
    """
    # Synthesize pairs with deliberate violation
    valid_pair_traces = [
        {
            "trace_id": "atk_0",
            "twin_trace_id": "ben_0",
            "is_history_dependent": True,
            "scenario_type": "attack",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {"bucket": "dest"}}],
        },
        {
            "trace_id": "ben_0",
            "twin_trace_id": "atk_0",
            "is_history_dependent": True,
            "scenario_type": "benign",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {"bucket": "dest"}}],
        },
    ]

    res_valid = verify_action_d_invariance(valid_pair_traces)
    assert res_valid.is_invariant is True
    assert res_valid.invariant_pairs == 1
    assert res_valid.evaluated_pairs == 1

    # Deliberately violate argument invariance
    violated_pair_traces = [
        {
            "trace_id": "atk_0",
            "twin_trace_id": "ben_0",
            "is_history_dependent": True,
            "scenario_type": "attack",
            "critical_step_index": 0,
            "actions": [
                {"step": 0, "tool": "export", "arguments": {"bucket": "dest", "leak": True}}
            ],
        },
        {
            "trace_id": "ben_0",
            "twin_trace_id": "atk_0",
            "is_history_dependent": True,
            "scenario_type": "benign",
            "critical_step_index": 0,
            "actions": [
                {"step": 0, "tool": "export", "arguments": {"bucket": "dest", "leak": False}}
            ],
        },
    ]

    res_violated = verify_action_d_invariance(violated_pair_traces)
    assert res_violated.is_invariant is False
    assert res_violated.invariant_pairs == 0
    assert res_violated.evaluated_pairs == 1


def test_h1_cluster_bootstrap_ci_computation() -> None:
    """
    Verifies that cluster bootstrap resamples pairs (clusters) and computes
    numeric confidence interval bounds, not hardcoded bounds.
    """
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    labels_by_id: dict[str, dict[str, Any]] = {}

    for i in range(8):
        atk_id = f"atk_{i}"
        ben_id = f"ben_{i}"
        atk = {
            "trace_id": atk_id,
            "twin_trace_id": ben_id,
            "is_history_dependent": True,
            "scenario_type": "attack",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {"id": i}}],
        }
        ben = {
            "trace_id": ben_id,
            "twin_trace_id": atk_id,
            "is_history_dependent": True,
            "scenario_type": "benign",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {"id": i}}],
        }
        pairs.append((atk, ben))
        labels_by_id[atk_id] = {"is_malicious": True}
        labels_by_id[ben_id] = {"is_malicious": False}

    # Case 1: Consistent evaluator on invariant actions -> J = 0 everywhere
    def _consistent_eval(act: dict[str, Any]) -> str:
        return "REVIEW"

    point_j, ci_l, ci_u, _, _, _ = cluster_bootstrap_b4(
        pairs, labels_by_id, _consistent_eval, n_replicates=100, seed=42
    )
    assert isinstance(ci_l, float)
    assert isinstance(ci_u, float)
    assert point_j == 0.0
    assert ci_l == 0.0
    assert ci_u == 0.0

    # Case 2: Evaluator with variation across pair IDs
    # e.g., flags only when id < 4
    def _id_sensitive_eval(act: dict[str, Any]) -> str:
        return "REVIEW" if act["arguments"]["id"] < 4 else "ALLOW"

    point_j2, ci_l2, ci_u2, _, _, _ = cluster_bootstrap_b4(
        pairs, labels_by_id, _id_sensitive_eval, n_replicates=100, seed=42
    )
    # Since atk and ben have the SAME id in each pair, J is still 0 on each resample
    assert point_j2 == 0.0
    assert ci_l2 == 0.0
    assert ci_u2 == 0.0


def test_h1_b3_and_b4_are_separate_checks() -> None:
    """
    Verifies that B3 and B4 are evaluated as separate paths with different criteria:
    - B3 requires J == 0.0 exactly.
    - B4 allows |J| <= 0.03 and 95% CI containing 0.
    """
    traces: list[dict[str, Any]] = [
        {
            "trace_id": "atk_0",
            "twin_trace_id": "ben_0",
            "is_history_dependent": True,
            "scenario_type": "attack",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {}}],
        },
        {
            "trace_id": "ben_0",
            "twin_trace_id": "atk_0",
            "is_history_dependent": True,
            "scenario_type": "benign",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {}}],
        },
    ]
    labels: list[dict[str, Any]] = [
        {"trace_id": "atk_0", "is_malicious": True},
        {"trace_id": "ben_0", "is_malicious": False},
    ]

    # Evaluate B3
    b3_res = evaluate_b3_determinism(traces, labels)
    assert isinstance(b3_res, B3CheckResult)
    assert b3_res.arm == "B3"
    assert b3_res.computed_j == 0.0
    assert b3_res.status == H1Status.PASS

    # Evaluate B4
    b4_res = evaluate_b4_stochastic(traces, labels, n_replicates=50)
    assert isinstance(b4_res, B4CheckResult)
    assert b4_res.arm == "B4"
    assert b4_res.computed_j == 0.0
    assert b4_res.ci_lower == 0.0
    assert b4_res.ci_upper == 0.0
    assert b4_res.status == H1Status.PASS


def test_h1_pass_on_canonical_dev_dataset() -> None:
    """Verifies that the canonical DEV dataset cleanly passes all H1 criteria via run_h1_check."""
    report = run_h1_check()

    assert report.status == H1Status.PASS
    assert report.pair_count == 8
    assert report.trace_count == 16
    assert report.action_d_invariance.is_invariant is True
    assert report.action_d_invariance.invariant_pairs == 8

    # B3 result
    assert report.b3_result.status == H1Status.PASS
    assert report.b3_result.computed_j == 0.0
    assert report.b3_result.tp == 8
    assert report.b3_result.fp == 8

    # B4 result
    assert report.b4_result.status == H1Status.PASS
    assert report.b4_result.computed_j == 0.0
    assert report.b4_result.ci_lower <= 0.0 <= report.b4_result.ci_upper

    # Check artifacts written
    assert Path("experiments/datasets/dev/h1_manipulation_check.json").exists()
    assert Path("experiments/reports/H1_manipulation_check.md").exists()


def test_h1_blocked_when_inputs_missing() -> None:
    """Verifies that if input files do not exist, status is BLOCKED, never fabricated PASS."""
    fake_traces = Path("experiments/datasets/dev/nonexistent_traces.jsonl")
    fake_labels = Path("experiments/datasets/dev/nonexistent_labels.jsonl")

    report = run_h1_check(traces_path=fake_traces, labels_path=fake_labels)
    assert report.status == H1Status.BLOCKED
    assert "Inputs unavailable" in report.reason

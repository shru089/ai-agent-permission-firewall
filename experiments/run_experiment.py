"""
Command-Line Experiment Harness for AI Agent Permission Firewall.

CLI entry point for running evaluation experiments:
- Supports Mode A (Offline Replay / Calibration) and Mode B (Closed-Loop / Prevention).
- Supports canonical arms: B0, B1, B2, B3, B4, B5, B6, P1 (and ALL).
- Strictly blocks access to held-out test data until PREREG-001 is committed and verified.
- Outputs structured JSON results with canonical metrics and cluster-bootstrap CIs.

Usage:
  python experiments/run_experiment.py --mode replay --arm B3 --split dev
  python experiments/run_experiment.py --mode closed_loop --arm P1 --split dev --reviewer oracle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure workspace root is in sys.path for direct script execution
_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

import experiments.metrics as metrics  # noqa: E402
from experiments.evaluate import (  # noqa: E402
    CANONICAL_ARMS,
    load_dataset,
    run_mode_a,
    run_mode_b,
    verify_test_split_access,
)


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AASF Reproducible Evaluation Experiment Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["replay", "closed_loop", "mode_a", "mode_b"],
        required=True,
        help="Evaluation mode: 'replay' (Mode A) or 'closed_loop' (Mode B)",
    )
    parser.add_argument(
        "--arm",
        choices=list(CANONICAL_ARMS) + ["ALL"],
        required=True,
        help="Benchmark arm to evaluate (or ALL)",
    )
    parser.add_argument(
        "--split",
        choices=["dev", "cal", "test", "test-in", "test-novel"],
        default="dev",
        help="Dataset split to evaluate",
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default=None,
        help="Optional path to trace file (.json, .jsonl) or directory",
    )
    parser.add_argument(
        "--reviewer",
        choices=["oracle", "reject-all", "noisy"],
        default="oracle",
        help="Reviewer simulation model for Mode B",
    )
    parser.add_argument(
        "--epsilon",
        type=float,
        default=None,
        help="Error rate epsilon for 'noisy' reviewer model (required if reviewer=noisy)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Optional directory to save evaluation JSON results",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic seeded sampling",
    )
    parser.add_argument(
        "--bootstrap-reps",
        type=int,
        default=1000,
        help="Number of cluster-bootstrap resamples for confidence intervals",
    )
    return parser.parse_args(args)


def main(args: list[str] | None = None) -> int:
    opts = parse_args(args)

    # Enforce test split preregistration guard immediately
    if opts.split.lower() in ("test", "test-in", "test-novel"):
        try:
            verify_test_split_access(opts.split)
        except PermissionError as pe:
            print(f"ERROR: {pe}", file=sys.stderr)
            return 2

    # Load traces
    try:
        traces = load_dataset(split=opts.split, dataset_path=opts.dataset_path)
    except FileNotFoundError as fnf:
        print(f"ERROR: {fnf}", file=sys.stderr)
        return 1

    if not traces:
        print(f"WARNING: Dataset split '{opts.split}' contains 0 traces.", file=sys.stderr)
        return 0

    arms_to_run = list(CANONICAL_ARMS) if opts.arm == "ALL" else [opts.arm]
    is_mode_a = opts.mode in ("replay", "mode_a")

    all_results: Dict[str, Any] = {
        "mode": opts.mode,
        "split": opts.split,
        "n_traces": len(traces),
        "arms": {},
    }

    for arm in arms_to_run:
        print(f"Evaluating Arm {arm} on {len(traces)} traces ({opts.mode})...")
        if is_mode_a:
            res_a = run_mode_a(
                traces=traces,
                arm=arm,
                seed=opts.seed,
                bootstrap_reps=opts.bootstrap_reps,
            )
            all_results["arms"][arm] = {
                "arm": arm,
                "n_decision_points": res_a.n_decision_points,
                "precision_crit": res_a.precision_crit,
                "recall_crit": res_a.recall_crit,
                "fpr_crit": res_a.fpr_crit,
                "f1_crit": res_a.f1_crit,
                "youden_j_crit": res_a.youden_j_crit,
                "recall_crit_ci": (
                    {"lower": res_a.recall_crit_ci.lower, "upper": res_a.recall_crit_ci.upper}
                    if res_a.recall_crit_ci
                    else None
                ),
                "fpr_crit_ci": (
                    {"lower": res_a.fpr_crit_ci.lower, "upper": res_a.fpr_crit_ci.upper}
                    if res_a.fpr_crit_ci
                    else None
                ),
                "youden_j_ci": (
                    {"lower": res_a.youden_j_ci.lower, "upper": res_a.youden_j_ci.upper}
                    if res_a.youden_j_ci
                    else None
                ),
                "latency_median_ms": res_a.latency_stats.median_ms,
                "latency_p95_ms": res_a.latency_stats.p95_ms,
                "policy_violations": metrics.count_policy_violations(res_a.decision_points_all),
            }
        else:
            res_b = run_mode_b(
                traces=traces,
                arm=arm,
                reviewer=opts.reviewer,
                epsilon=opts.epsilon,
                seed=opts.seed,
                bootstrap_reps=opts.bootstrap_reps,
            )
            all_results["arms"][arm] = {
                "arm": arm,
                "reviewer": opts.reviewer,
                "epsilon": opts.epsilon,
                "n_traces": res_b.n_traces,
                "m_adr": res_b.metrics.m_adr,
                "m_apr": res_b.metrics.m_apr,
                "m_uar": res_b.metrics.m_uar,
                "m_lts": res_b.metrics.m_lts,
                "m_lts_0": res_b.metrics.m_lts_0,
                "m_fpr_t": res_b.metrics.m_fpr_t,
                "m_revr": res_b.metrics.m_revr,
                "m_viol": metrics.count_policy_violations(res_b.decision_points),
                "apr_ci": (
                    {"lower": res_b.apr_ci.lower, "upper": res_b.apr_ci.upper}
                    if res_b.apr_ci
                    else None
                ),
                "lts_ci": (
                    {"lower": res_b.lts_ci.lower, "upper": res_b.lts_ci.upper}
                    if res_b.lts_ci
                    else None
                ),
                "latency_median_ms": res_b.latency_stats.median_ms,
                "latency_p95_ms": res_b.latency_stats.p95_ms,
            }

    # Print summary
    print("\n=== Evaluation Results Summary ===")
    print(json.dumps(all_results, indent=2))

    if opts.output_dir:
        out_p = Path(opts.output_dir)
        out_p.mkdir(parents=True, exist_ok=True)
        out_file = out_p / f"eval_{opts.mode}_{opts.split}_{opts.arm}.json"
        out_file.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
        print(f"\nWrote full evaluation results to {out_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

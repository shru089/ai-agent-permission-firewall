"""
T-EXP-002: Automated Action-D Invariance Tests.

Source: docs/03_MATHEMATICAL_MODEL_AND_METRICS.md §7.1, docs/06_EXPERIMENT_PROTOCOL.md §5.2.
Verifies that for every matched history-dependent pair (τ⁺, τ⁻), the proposed action at
critical step t* is byte-for-byte identical, prior history diverges, labels diverge,
and zero classification leakage tokens are present.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from experiments.generator.pairing import ActionDInvarianceChecker
from experiments.labels.oracle import SpecificationLabelOracle


@pytest.fixture
def dev_traces() -> list[dict[str, Any]]:
    traces_file = Path("experiments/datasets/dev/traces.jsonl")
    assert traces_file.exists(), "traces.jsonl does not exist. Run generator CLI first."
    traces: list[dict[str, Any]] = []
    with open(traces_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                traces.append(json.loads(line))
    return traces


@pytest.fixture
def dev_labels() -> list[dict[str, Any]]:
    labels_file = Path("experiments/datasets/dev/labels.jsonl")
    assert labels_file.exists(), "labels.jsonl does not exist. Run generator CLI first."
    labels: list[dict[str, Any]] = []
    with open(labels_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                labels.append(json.loads(line))
    return labels


def test_t_exp_002_action_d_invariance_on_canonical_dataset(
    dev_traces: list[dict[str, Any]],
    dev_labels: list[dict[str, Any]],
) -> None:
    """Verifies that all history-dependent pairs in DEV pass Action-D invariance."""
    oracle = SpecificationLabelOracle()
    checker = ActionDInvarianceChecker(oracle)

    passed, pair_matches, summary = checker.verify_dataset(dev_traces, dev_labels)

    assert passed is True, f"Action-D invariance check failed: {summary}"
    assert summary["valid_pairs"] > 0, "No valid history-dependent pairs found in dataset."
    assert summary["failed_pairs"] == 0, f"Some pairs failed invariance: {pair_matches}"


def test_action_d_invariance_tamper_detection(
    dev_traces: list[dict[str, Any]],
    dev_labels: list[dict[str, Any]],
) -> None:
    """Verifies that tampering with Action D in a pair triggers invariance failure."""
    oracle = SpecificationLabelOracle()
    checker = ActionDInvarianceChecker(oracle)

    # Make deep copy of traces
    tampered_traces = [dict(t) for t in dev_traces]
    for i, t in enumerate(tampered_traces):
        tampered_traces[i] = json.loads(json.dumps(t))

    # Find first history-dependent attack trace and tamper with its Action D arguments
    for t in tampered_traces:
        if t.get("is_history_dependent") and t.get("scenario_type") == "attack":
            t_star = t["critical_step_index"]
            t["actions"][t_star]["arguments"]["batch_size"] = 999999
            break

    passed, _, summary = checker.verify_dataset(tampered_traces, dev_labels)
    assert passed is False, "Checker failed to detect tampered Action D arguments!"
    assert summary["failed_pairs"] >= 1


def test_action_d_invariance_history_divergence_requirement(
    dev_traces: list[dict[str, Any]],
    dev_labels: list[dict[str, Any]],
) -> None:
    """Verifies that if histories are forced to be identical, invariance check fails."""
    oracle = SpecificationLabelOracle()
    checker = ActionDInvarianceChecker(oracle)

    tampered_traces = [json.loads(json.dumps(t)) for t in dev_traces]

    # Find a pair and overwrite benign trace history with attack trace history
    atk_trace = next(t for t in tampered_traces if t.get("is_history_dependent") and t.get("scenario_type") == "attack")
    twin_id = atk_trace["twin_trace_id"]
    ben_trace = next(t for t in tampered_traces if t["trace_id"] == twin_id)

    t_star = atk_trace["critical_step_index"]
    ben_trace["actions"][:t_star] = json.loads(json.dumps(atk_trace["actions"][:t_star]))

    passed, _, summary = checker.verify_dataset(tampered_traces, dev_labels)
    assert passed is False, "Checker failed to detect identical prior history!"

"""
Tests for H1 Manipulation-Check Acceptance Validator.

Verifies:
1. Validator uses exclusively the authoritative criterion from docs/06 and PREREG-001.
2. No invented tolerances: B3 requires J = 0 exactly.
3. If formal criterion is absent, result is strictly BLOCKED.
4. PASS/FAIL behavior matches formal criteria on canonical DEV dataset and synthetic manipulations.
"""

from pathlib import Path
from typing import Any

import pytest

from experiments.validation.h1_manipulation_check import (
    AUTHORITATIVE_CRITERIA,
    H1ManipulationCheckValidator,
    H1ValidationResult,
    H1ValidationStatus,
    run_h1_validation_on_dev,
)


def test_h1_authoritative_criterion_source_and_quote() -> None:
    """Verifies that the validator records the exact source file, line/section, and quoted criterion."""
    validator = H1ManipulationCheckValidator()
    assert validator.criterion_metadata["protocol_file"] == "docs/06_EXPERIMENT_PROTOCOL.md"
    assert "§2.1" in validator.criterion_metadata["protocol_section"]
    assert "§2.2" in validator.criterion_metadata["protocol_section"]
    assert "J = 0 exactly" in validator.criterion_metadata["b3_quoted_criterion"]
    assert "absolute J <= 0.03" in validator.criterion_metadata["b4_quoted_criterion"]
    assert "95% cluster-bootstrap confidence interval including 0" in validator.criterion_metadata["b4_quoted_criterion"]


def test_h1_blocked_when_criterion_is_absent() -> None:
    """Verifies that if no formal criterion is found, the validator returns BLOCKED without inventing a threshold."""
    empty_validator = H1ManipulationCheckValidator(criterion_metadata={})

    dummy_traces: list[dict[str, Any]] = [
        {
            "trace_id": "t1",
            "twin_trace_id": "t2",
            "is_history_dependent": True,
            "scenario_type": "attack",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {}}],
        },
        {
            "trace_id": "t2",
            "twin_trace_id": "t1",
            "is_history_dependent": True,
            "scenario_type": "benign",
            "critical_step_index": 0,
            "actions": [{"step": 0, "tool": "export", "arguments": {}}],
        },
    ]
    dummy_labels: list[dict[str, Any]] = [
        {"trace_id": "t1", "verdict": "MALICIOUS", "label": 1},
        {"trace_id": "t2", "verdict": "BENIGN", "label": 0},
    ]

    result = empty_validator.validate_b3_determinism(dummy_traces, dummy_labels)

    assert result.status == H1ValidationStatus.BLOCKED
    assert "No formally established manipulation-check acceptance criterion found" in result.reason
    assert result.computed_j is None


def test_h1_b3_no_invented_tolerance() -> None:
    """
    Verifies that B3 enforces exact numerical equality (J == 0.0)
    and does not accept a small invented epsilon or tolerance.
    """
    validator = H1ManipulationCheckValidator()

    # Construct paired traces where evaluator is manipulated to have slight leakage
    traces: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []

    # 100 pairs: 99 identical, 1 where attack is flagged and benign is not
    for i in range(100):
        t_atk = f"atk_{i}"
        t_ben = f"ben_{i}"
        traces.extend([
            {
                "trace_id": t_atk,
                "twin_trace_id": t_ben,
                "is_history_dependent": True,
                "scenario_type": "attack",
                "critical_step_index": 0,
                "actions": [{"step": 0, "tool": "export", "arguments": {"id": i, "is_atk": True}}],
            },
            {
                "trace_id": t_ben,
                "twin_trace_id": t_atk,
                "is_history_dependent": True,
                "scenario_type": "benign",
                "critical_step_index": 0,
                "actions": [{"step": 0, "tool": "export", "arguments": {"id": i, "is_atk": False}}],
            },
        ])
        labels.extend([
            {"trace_id": t_atk, "verdict": "MALICIOUS", "label": 1},
            {"trace_id": t_ben, "verdict": "BENIGN", "label": 0},
        ])

    # Evaluator flags only when id == 0 and is_atk is True -> J = 1/100 - 0 = 0.01
    def _leaky_evaluator(act: dict[str, Any]) -> str:
        args = act.get("arguments", {})
        if args.get("id") == 0 and args.get("is_atk"):
            return "DENY"
        return "ALLOW"

    result = validator.validate_b3_determinism(traces, labels, b3_evaluator=_leaky_evaluator)

    # Even though J = 0.01 is small (< 0.03), B3 requires J = 0 exactly!
    assert result.computed_j == 0.01
    assert result.status == H1ValidationStatus.FAIL
    assert "B3 violates exact criterion" in result.reason


def test_h1_pass_on_canonical_dev_dataset() -> None:
    """Verifies that the canonical DEV dataset cleanly passes the H1 manipulation check with J = 0.0 exactly."""
    result = run_h1_validation_on_dev()

    assert result.status == H1ValidationStatus.PASS
    assert result.computed_j == 0.0
    assert result.pair_count == 8
    assert result.trace_count == 16
    assert result.recall == result.fpr
    assert "B3 satisfies exact criterion (J = 0.0000 == 0.0)" in result.reason

    # Verify JSON and MD artifacts exist
    assert Path("experiments/datasets/dev/h1_manipulation_check.json").exists()
    assert Path("experiments/reports/H1_manipulation_check.md").exists()


def test_h1_b4_stochastic_thresholds() -> None:
    """Verifies that B4 validator applies the exact formal rule: |J| <= 0.03 and CI includes 0."""
    validator = H1ManipulationCheckValidator()

    # Case 1: Pass (|J| <= 0.03 and CI includes 0)
    res_pass = validator.validate_b4_stochastic(j_value=0.015, ci_lower=-0.01, ci_upper=0.025)
    assert res_pass.status == H1ValidationStatus.PASS

    # Case 2: Fail because |J| > 0.03
    res_fail_bound = validator.validate_b4_stochastic(j_value=0.045, ci_lower=-0.01, ci_upper=0.06)
    assert res_fail_bound.status == H1ValidationStatus.FAIL

    # Case 3: Fail because 95% CI strictly excludes 0
    res_fail_ci = validator.validate_b4_stochastic(j_value=0.02, ci_lower=0.005, ci_upper=0.028)
    assert res_fail_ci.status == H1ValidationStatus.FAIL

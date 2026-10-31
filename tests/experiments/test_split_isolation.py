"""
T-EXP-005: Split Disjointness and Isolation Tests.

Source: docs/05_TECHNICAL_SPEC.md §8, docs/06_EXPERIMENT_PROTOCOL.md §3.
Verifies split disjointness by template family/variant and confirms complete absence
of evaluation / test contamination in the DEV handoff package.
"""

import json
from pathlib import Path
from typing import Any

from experiments.generator.scenarios import (
    ALL_TEMPLATES,
    CAL_TEMPLATES,
    DEV_TEMPLATES,
    TEST_IN_TEMPLATES,
    TEST_NOVEL_TEMPLATES,
)


def test_t_exp_005_templates_are_pairwise_disjoint() -> None:
    """Verifies that all registered templates across DEV, CAL, TEST-IN, and TEST-NOVEL are mutually disjoint."""
    dev_ids = {t.template_id for t in DEV_TEMPLATES}
    cal_ids = {t.template_id for t in CAL_TEMPLATES}
    test_in_ids = {t.template_id for t in TEST_IN_TEMPLATES}
    test_novel_ids = {t.template_id for t in TEST_NOVEL_TEMPLATES}

    # Verify no overlaps
    assert dev_ids.isdisjoint(cal_ids), f"Overlap between DEV and CAL: {dev_ids & cal_ids}"
    assert dev_ids.isdisjoint(test_in_ids), f"Overlap between DEV and TEST-IN: {dev_ids & test_in_ids}"
    assert dev_ids.isdisjoint(test_novel_ids), f"Overlap between DEV and TEST-NOVEL: {dev_ids & test_novel_ids}"
    assert cal_ids.isdisjoint(test_in_ids), f"Overlap between CAL and TEST-IN: {cal_ids & test_in_ids}"
    assert cal_ids.isdisjoint(test_novel_ids), f"Overlap between CAL and TEST-NOVEL: {cal_ids & test_novel_ids}"
    assert test_in_ids.isdisjoint(test_novel_ids), f"Overlap between TEST-IN and TEST-NOVEL: {test_in_ids & test_novel_ids}"

    total_expected = len(dev_ids) + len(cal_ids) + len(test_in_ids) + len(test_novel_ids)
    assert len(ALL_TEMPLATES) == total_expected, "Total template count mismatch."


def test_canonical_dev_traces_contain_only_dev_split() -> None:
    """Verifies that every trace in the canonical DEV traces.jsonl is strictly assigned to DEV split."""
    traces_file = Path("experiments/datasets/dev/traces.jsonl")
    assert traces_file.exists()

    cal_test_ids = {
        t.template_id for t in (CAL_TEMPLATES + TEST_IN_TEMPLATES + TEST_NOVEL_TEMPLATES)
    }

    with open(traces_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            trace: dict[str, Any] = json.loads(line)
            assert trace["split"] == "DEV", f"Trace {trace['trace_id']} has non-DEV split: {trace['split']}"
            assert trace["template_id"] not in cal_test_ids, (
                f"Trace {trace['trace_id']} uses held-out template: {trace['template_id']}"
            )
            assert trace["used_in_development_or_calibration"] is True


def test_split_isolation_metadata_artifact() -> None:
    """Verifies that split_isolation.json metadata is valid and reports zero overlaps."""
    split_file = Path("experiments/datasets/dev/split_isolation.json")
    assert split_file.exists()

    data = json.loads(split_file.read_text(encoding="utf-8"))
    assert data["isolation_verified"] is True
    assert data["dev_templates_count"] == len(DEV_TEMPLATES)
    assert data["cal_templates_count"] == len(CAL_TEMPLATES)
    assert data["test_in_templates_count"] == len(TEST_IN_TEMPLATES)
    assert data["test_novel_templates_count"] == len(TEST_NOVEL_TEMPLATES)

    for overlap_name, overlap_list in data["pairwise_overlaps"].items():
        assert len(overlap_list) == 0, f"Non-empty overlap found in {overlap_name}: {overlap_list}"

    assert data["dev_trace_splits_found"] == ["DEV"]

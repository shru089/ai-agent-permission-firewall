"""
T-EXP-001: Generator Determinism and Provenance Tests.

Source: docs/05_TECHNICAL_SPEC.md §8 (T-EXP-001), docs/04_PRD.md FR-EXP-01.
Verifies that:
1. Generator produces byte-identical datasets for equal random seeds.
2. Distinct seeds produce distinct, properly attributed datasets.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from experiments.generator.cli import generate_dev_dataset


def test_t_exp_001_seed_determinism() -> None:
    """Verifies that two independent generation runs with the same seed produce byte-identical traces and labels."""
    with TemporaryDirectory() as tmp1, TemporaryDirectory() as tmp2:
        dir1 = Path(tmp1)
        dir2 = Path(tmp2)

        res1 = generate_dev_dataset(
            seed=42,
            variants_per_template=1,
            output_dir=dir1 / "dev",
            reports_dir=dir1 / "reports",
        )
        res2 = generate_dev_dataset(
            seed=42,
            variants_per_template=1,
            output_dir=dir2 / "dev",
            reports_dir=dir2 / "reports",
        )

        assert res1["record_count"] == res2["record_count"]

        # Traces must be byte-identical
        traces1 = (dir1 / "dev" / "traces.jsonl").read_bytes()
        traces2 = (dir2 / "dev" / "traces.jsonl").read_bytes()
        assert traces1 == traces2, "Traces generated with identical seeds diverged!"

        # Labels must be byte-identical
        labels1 = (dir1 / "dev" / "labels.jsonl").read_bytes()
        labels2 = (dir2 / "dev" / "labels.jsonl").read_bytes()
        assert labels1 == labels2, "Labels generated with identical seeds diverged!"


def test_seed_variation_changes_trace_ids() -> None:
    """Verifies that changing seed propagates to trace identifiers."""
    with TemporaryDirectory() as tmp1, TemporaryDirectory() as tmp2:
        dir1 = Path(tmp1)
        dir2 = Path(tmp2)

        generate_dev_dataset(
            seed=101,
            variants_per_template=1,
            output_dir=dir1 / "dev",
            reports_dir=dir1 / "reports",
        )
        generate_dev_dataset(
            seed=202,
            variants_per_template=1,
            output_dir=dir2 / "dev",
            reports_dir=dir2 / "reports",
        )

        traces1 = [json.loads(l) for l in (dir1 / "dev" / "traces.jsonl").read_text().splitlines() if l.strip()]
        traces2 = [json.loads(l) for l in (dir2 / "dev" / "traces.jsonl").read_text().splitlines() if l.strip()]

        ids1 = {t["trace_id"] for t in traces1}
        ids2 = {t["trace_id"] for t in traces2}

        assert ids1.isdisjoint(ids2), "Trace IDs from different seeds collided!"

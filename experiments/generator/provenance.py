"""
Provenance Metadata Generator for Dataset Handoff Package (C10/C11).

Generates provenance.json documenting seed reproducibility, schema versions,
generator code integrity, and environment details.
"""

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def compute_generator_code_hash() -> str:
    """Computes SHA-256 hash over generator and oracle source files for provenance integrity."""
    hasher = hashlib.sha256()
    repo_root = Path(__file__).resolve().parent.parent.parent

    target_files = [
        repo_root / "experiments" / "generator" / "scenarios.py",
        repo_root / "experiments" / "generator" / "trace_builder.py",
        repo_root / "experiments" / "generator" / "pairing.py",
        repo_root / "experiments" / "generator" / "cli.py",
        repo_root / "experiments" / "labels" / "rules.py",
        repo_root / "experiments" / "labels" / "oracle.py",
    ]

    for p in target_files:
        if p.exists():
            hasher.update(p.name.encode("utf-8"))
            hasher.update(p.read_bytes())

    return hasher.hexdigest()


def generate_provenance_record(
    seed: int,
    record_count: int,
    template_count: int,
    family_counts: dict[str, int],
    split: str = "DEV",
    dataset_version: str = "1.0.0",
    protocol_version: str = "docs/06_EXPERIMENT_PROTOCOL.md v1.0 §5.4",
    generator_version: str = "1.0.0",
    label_oracle_version: str = "1.0.0",
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    """Builds the canonical provenance.json dictionary."""
    gen_hash = compute_generator_code_hash()
    now_iso = timestamp or datetime.now(timezone.utc).isoformat()

    return {
        "dataset_version": dataset_version,
        "protocol_version": protocol_version,
        "generator_version": generator_version,
        "generator_hash": gen_hash,
        "generated_at_utc": now_iso,
        "seed": seed,
        "python_version": sys.version,
        "schema_version": "5.4-canonical",
        "label_oracle_version": label_oracle_version,
        "record_count": record_count,
        "template_count": template_count,
        "family_counts": family_counts,
        "split": split,
        "checksum_algorithm": "SHA-256",
        "canonical_json_algorithm": "RFC-8785",
        "inputs": [
            "docs/06_EXPERIMENT_PROTOCOL.md §3, §5.4",
            "docs/03_MATHEMATICAL_MODEL_AND_METRICS.md §7",
            "experiments/generator/scenarios.py",
            "experiments/labels/rules.py",
        ],
        "transformations": [
            "Deterministic scenario template instantiation",
            "Matched history-dependent twin linking",
            "RFC-8785 canonical digest computation per trace",
            "Independent specification label oracle evaluation",
            "Action-D invariance verification (T-EXP-002)",
            "Template family split disjointness validation (T-EXP-005)",
            "SHA-256 manifest generation",
        ],
        "notes": (
            "Canonical DEV dataset handoff package for Shrishti. "
            "Isolated to DEV split templates only; zero CAL or TEST traces present. "
            "All history-dependent pairs strictly satisfy Action-D invariance."
        ),
    }

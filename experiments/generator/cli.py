"""
Command-Line Interface for Deterministic Scenario Generator (C10/C11).

Generates canonical benchmark datasets (DEV, CAL, TEST-IN, TEST-NOVEL), labels,
provenance, audit logs, verification reports, and manifest.sha256.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from experiments.generator.pairing import ActionDInvarianceChecker
from experiments.generator.provenance import generate_provenance_record
from experiments.generator.scenarios import (
    ALL_TEMPLATES,
    CAL_TEMPLATES,
    DEV_TEMPLATES,
    TEST_IN_TEMPLATES,
    TEST_NOVEL_TEMPLATES,
    ScenarioTemplate,
)
from experiments.generator.trace_builder import TraceBuilder
from experiments.labels.oracle import SpecificationLabelOracle


def compute_sha256(file_path: Path) -> str:
    """Computes standard hex SHA-256 for a given file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_templates_for_split(split_name: str) -> list[ScenarioTemplate]:
    """Resolve scenario templates for a given split name."""
    s = split_name.strip().upper()
    if s == "DEV":
        return DEV_TEMPLATES
    if s == "CAL":
        return CAL_TEMPLATES
    if s in ("TEST-IN", "TEST_IN"):
        return TEST_IN_TEMPLATES
    if s in ("TEST-NOVEL", "TEST_NOVEL"):
        return TEST_NOVEL_TEMPLATES
    raise ValueError(f"Unknown split: {split_name!r}. Supported: DEV, CAL, TEST-IN, TEST-NOVEL")


def generate_split_dataset(
    split: str = "DEV",
    seed: int = 20261031,
    variants_per_template: int = 2,
    output_dir: Optional[Path] = None,
    reports_dir: Optional[Path] = None,
    spec_path: str = "docs/06_EXPERIMENT_PROTOCOL.md",
) -> dict[str, Any]:
    """Generates the full canonical dataset package for any designated split."""
    split_norm = split.strip().upper()
    templates = get_templates_for_split(split_norm)

    if output_dir is None:
        split_slug = split_norm.lower()
        output_dir = Path("experiments") / "datasets" / split_slug

    output_dir.mkdir(parents=True, exist_ok=True)
    if reports_dir is not None:
        reports_dir.mkdir(parents=True, exist_ok=True)

    builder = TraceBuilder()
    oracle = SpecificationLabelOracle()
    checker = ActionDInvarianceChecker(oracle)

    traces: list[dict[str, Any]] = []

    # Map paired templates to resolve twin IDs
    paired_map: dict[str, str] = {}
    for tpl in templates:
        if tpl.is_history_dependent and tpl.twin_template_id:
            paired_map[tpl.template_id] = tpl.twin_template_id

    # Generate traces for each template and variant
    for var_idx in range(variants_per_template):
        for tpl in templates:
            twin_trace_id = None
            if tpl.template_id in paired_map:
                twin_tpl_short = paired_map[tpl.template_id].replace("tpl_", "")
                twin_trace_id = f"{twin_tpl_short}_v{var_idx:02d}_s{seed}"

            trace = builder.build_trace(
                template=tpl,
                variant_idx=var_idx,
                seed=seed,
                twin_trace_id=twin_trace_id,
            )
            traces.append(trace)

    # 1. Write traces.jsonl
    traces_file = output_dir / "traces.jsonl"
    with open(traces_file, "w", encoding="utf-8", newline="\n") as f:
        for t in traces:
            f.write(json.dumps(t) + "\n")

    # 2. Evaluate labels & write labels.jsonl
    labels: list[dict[str, Any]] = []
    labels_file = output_dir / "labels.jsonl"
    with open(labels_file, "w", encoding="utf-8", newline="\n") as f:
        for t in traces:
            lbl = oracle.evaluate_trace(t)
            lbl_dict = lbl.to_dict()
            labels.append(lbl_dict)
            f.write(json.dumps(lbl_dict) + "\n")

    # 3. Label audit log for T-EXP-005
    audit_records: list[dict[str, Any]] = []
    audit_file = output_dir / "label_audit.jsonl"
    with open(audit_file, "w", encoding="utf-8", newline="\n") as f:
        for t in traces:
            audit_rec = oracle.audit_trace(t)
            audit_records.append(audit_rec)
            f.write(json.dumps(audit_rec) + "\n")

    # 4. Verify Action-D Invariance (T-EXP-002)
    inv_passed, pair_matches, inv_summary = checker.verify_dataset(traces, labels)
    if not inv_passed:
        raise ValueError(
            f"Action-D invariance verification failed for {split_norm}: {inv_summary}"
        )

    # 5. Split Isolation Check (T-EXP-005)
    dev_ids = {t.template_id for t in DEV_TEMPLATES}
    cal_ids = {t.template_id for t in CAL_TEMPLATES}
    test_in_ids = {t.template_id for t in TEST_IN_TEMPLATES}
    test_novel_ids = {t.template_id for t in TEST_NOVEL_TEMPLATES}

    dev_cal_overlap = dev_ids.intersection(cal_ids)
    dev_test_in_overlap = dev_ids.intersection(test_in_ids)
    dev_test_novel_overlap = dev_ids.intersection(test_novel_ids)
    cal_test_overlap = cal_ids.intersection(test_in_ids | test_novel_ids)

    splits_disjoint = not (
        dev_cal_overlap or dev_test_in_overlap or dev_test_novel_overlap or cal_test_overlap
    )

    # Verify zero cross-split leakage
    trace_splits = {t["split"] for t in traces}
    zero_leakage = trace_splits == {split_norm}

    split_isolation_data = {
        "isolation_verified": splits_disjoint and zero_leakage,
        "split": split_norm,
        "dev_templates_count": len(dev_ids),
        "cal_templates_count": len(cal_ids),
        "test_in_templates_count": len(test_in_ids),
        "test_novel_templates_count": len(test_novel_ids),
        "total_templates_registered": len(ALL_TEMPLATES),
        "pairwise_overlaps": {
            "dev_vs_cal": list(dev_cal_overlap),
            "dev_vs_test_in": list(dev_test_in_overlap),
            "dev_vs_test_novel": list(dev_test_novel_overlap),
            "cal_vs_test": list(cal_test_overlap),
        },
        "dev_trace_splits_found": list(trace_splits),
        "trace_splits_found": list(trace_splits),
        "dev_templates": sorted(dev_ids),
        "cal_templates": sorted(cal_ids),
        "test_in_templates": sorted(test_in_ids),
        "test_novel_templates": sorted(test_novel_ids),
        "split_templates": sorted({t.template_id for t in templates}),
    }

    split_file = output_dir / "split_isolation.json"
    with open(split_file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(split_isolation_data, f, indent=2)
        f.write("\n")

    # 6. Provenance metadata
    family_counts: dict[str, int] = {}
    for t in traces:
        fam = t["family_id"]
        family_counts[fam] = family_counts.get(fam, 0) + 1

    prov_record = generate_provenance_record(
        seed=seed,
        record_count=len(traces),
        template_count=len(templates),
        family_counts=family_counts,
        split=split_norm,
        timestamp="2026-10-31T12:00:00+00:00",
    )
    prov_file = output_dir / "provenance.json"
    with open(prov_file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(prov_record, f, indent=2)
        f.write("\n")

    # 7. Dataset README
    readme_file = output_dir / "README.md"
    readme_content = f"""# Canonical {split_norm} Dataset Package

## Overview
This directory contains the canonical {split_norm} benchmark dataset for the
Adaptive Agentic Security Firewall (AASF).
It is generated offline and deterministically per `docs/06_EXPERIMENT_PROTOCOL.md` §3 and §5.4.

## Key Properties
- **Split:** {split_norm} (strictly isolated across benchmark splits).
- **Total Traces:** {len(traces)} across {len(templates)} templates.
- **Random Seed:** `{seed}` (100% reproducible).
- **Action-D Invariance (T-EXP-002):** Passed across all {len(pair_matches)} pairs.
- **Independent Label Oracle (T-EXP-009):** Evaluated against specification rules
  without runtime firewall engine imports.

## Delivered Artifacts
- `traces.jsonl`: Multi-step agent traces in canonical §5.4 schema.
- `labels.jsonl`: Specification-level ground-truth classifications.
- `provenance.json`: Generator metadata, git commit hash, environment, and seed tracking.
- `split_isolation.json`: Formal proof of template disjointness across benchmark splits.
- `label_audit.jsonl`: Complete rule-level audit evaluations (T-EXP-005).
- `manifest.sha256`: Cryptographic SHA-256 integrity checksums for all files.

## Family Breakdown
{chr(10).join(f"- **{fam}:** {cnt} traces" for fam, cnt in sorted(family_counts.items()))}
"""
    readme_file.write_text(readme_content, encoding="utf-8", newline="\n")

    # 8. Compute manifest.sha256 (for all delivered files in output_dir)
    manifest_file = output_dir / "manifest.sha256"
    delivered_files = sorted(
        [p for p in output_dir.iterdir() if p.is_file() and p.name != "manifest.sha256"]
    )

    manifest_lines: list[str] = []
    for p in delivered_files:
        sha = compute_sha256(p)
        manifest_lines.append(f"{sha}  {p.name}")

    manifest_file.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8", newline="\n")

    # 9. Generate Reports if reports_dir provided
    if reports_dir is not None:
        report_t_exp_002 = reports_dir / f"T-EXP-002_action_d_invariance_{split_norm.lower()}.md"
        report_t_exp_002_content = f"""# T-EXP-002 Action-D Invariance Test Report ({split_norm})

## Status: PASSED (100% Invariant)

## Reference
- **Source:** `docs/03_MATHEMATICAL_MODEL_AND_METRICS.md` §7.1,
  `docs/06_EXPERIMENT_PROTOCOL.md` §5.2
- **Requirement:** For every matched history-dependent pair,
  critical action at step $t^*$ is identical.

## Summary Metrics
- **Total Traces:** {len(traces)}
- **Total Pairs Evaluated:** {inv_summary["total_pairs_evaluated"]}
- **Valid Invariant Pairs:** {inv_summary["valid_pairs"]}
- **Failed Pairs:** {inv_summary["failed_pairs"]}
"""
        report_t_exp_002.write_text(report_t_exp_002_content, encoding="utf-8", newline="\n")

    return {
        "split": split_norm,
        "record_count": len(traces),
        "template_count": len(templates),
        "family_counts": family_counts,
        "inv_passed": inv_passed,
        "splits_disjoint": splits_disjoint,
        "manifest_path": str(manifest_file),
    }


def generate_dev_dataset(
    seed: int = 20261031,
    variants_per_template: int = 2,
    output_dir: Path = Path("experiments/datasets/dev"),
    reports_dir: Path = Path("experiments/reports"),
    spec_path: str = "docs/06_EXPERIMENT_PROTOCOL.md",
) -> dict[str, Any]:
    """Generates the full canonical DEV dataset handoff package (backward compatible)."""
    return generate_split_dataset(
        split="DEV",
        seed=seed,
        variants_per_template=variants_per_template,
        output_dir=output_dir,
        reports_dir=reports_dir,
        spec_path=spec_path,
    )


def generate_all_splits(
    seed: int = 20261031,
    variants_per_template: int = 2,
    base_dir: Path = Path("experiments/datasets"),
    reports_dir: Path = Path("experiments/reports"),
) -> dict[str, Any]:
    """
    Generates all 4 canonical splits (DEV, CAL, TEST-IN, TEST-NOVEL)
    and seals test commitment.
    """
    results: dict[str, Any] = {}
    splits = ["DEV", "CAL", "TEST-IN", "TEST-NOVEL"]

    for sp in splits:
        sp_slug = sp.lower()
        res = generate_split_dataset(
            split=sp,
            seed=seed,
            variants_per_template=variants_per_template,
            output_dir=base_dir / sp_slug,
            reports_dir=reports_dir,
        )
        results[sp] = res

    # Write test commitment hash manifest (D-10, D-38, Phase 5)
    commitment_dir = Path("docs/prereg")
    commitment_dir.mkdir(parents=True, exist_ok=True)
    commitment_file = commitment_dir / "TEST_COMMITMENT.sha256"

    commitment_lines: list[str] = []
    for test_split in ["test-in", "test-novel"]:
        split_path = base_dir / test_split
        for fname in ["manifest.sha256", "traces.jsonl", "labels.jsonl"]:
            fpath = split_path / fname
            if fpath.exists():
                sha = compute_sha256(fpath)
                commitment_lines.append(f"{sha}  experiments/datasets/{test_split}/{fname}")

    commitment_file.write_text("\n".join(commitment_lines) + "\n", encoding="utf-8", newline="\n")
    results["commitment_manifest"] = str(commitment_file)

    return results


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Deterministic AI Agent Dataset Generator")
    parser.add_argument(
        "--spec", default="docs/06_EXPERIMENT_PROTOCOL.md", help="Protocol spec path"
    )
    parser.add_argument("--seed", type=int, default=20261031, help="Deterministic generator seed")
    parser.add_argument("--output", default=None, help="Output directory")
    parser.add_argument(
        "--split", default="dev", help="Target split (dev, cal, test-in, test-novel, all)"
    )
    parser.add_argument("--variants", type=int, default=2, help="Variants per template")
    parser.add_argument("--reports", default="experiments/reports", help="Reports directory")

    args = parser.parse_args()

    target_split = args.split.strip().lower()
    if target_split == "all":
        print(f"[+] Generating ALL benchmark splits (seed={args.seed})...")
        res_all = generate_all_splits(
            seed=args.seed,
            variants_per_template=args.variants,
            base_dir=Path("experiments/datasets"),
            reports_dir=Path(args.reports),
        )
        msg = f"[+] All splits generated. Test commitment sealed: {res_all['commitment_manifest']}"
        print(msg)
    else:
        out_dir = Path(args.output) if args.output else Path("experiments/datasets") / target_split
        s_name = target_split.upper()
        start_msg = f"[+] Starting dataset generation for split: {s_name} (seed={args.seed})"
        print(start_msg)
        res = generate_split_dataset(
            split=target_split,
            seed=args.seed,
            variants_per_template=args.variants,
            output_dir=out_dir,
            reports_dir=Path(args.reports),
            spec_path=args.spec,
        )
        print(
            f"[+] Generation complete: {res['record_count']} traces "
            f"across {res['template_count']} templates."
        )
        print(f"[+] Manifest generated: {res['manifest_path']}")


if __name__ == "__main__":
    main()

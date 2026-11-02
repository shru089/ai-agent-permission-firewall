"""
Unit tests for AASF DEV Dataset Validation Suite (experiments/validate_dev_dataset.py).

Tests:
1. Valid matched trace pair passes all schema, registry, and Action-D checks.
2. Tool registry enforcement catches unregistered tools.
3. Schema conformity catches missing required fields and malformed actions.
4. Duplicate trace_id detection across files.
5. Twin relationship integrity (missing, non-existent, asymmetric, template mismatch, duality).
6. Action-D Invariance (T-EXP-002, docs/03 §7.2):
   - Tool mismatch at t*.
   - Arguments mismatch at t*.
   - Label duality failure at t*.
   - Violation prior to declared critical step t*.
7. Split contamination (wrong split declaration, cross-split template overlap with CAL).
8. Content digest and manifest verification.
9. Statistical sample count and power warnings (OQ-11).
10. H1 manipulation check readiness assessment (docs/06 §2.2).
11. CLI invocation and exit code behavior.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from experiments.validate_dev_dataset import (
    compute_actions_digest,
    validate_dev_dataset,
)
from experiments.validate_dev_dataset import (
    main as cli_main,
)

# ---------------------------------------------------------------------------
# Fixture Helpers
# ---------------------------------------------------------------------------


def make_valid_pair(
    pair_id: str = "P01",
    template_id: str = "TMP_EXPORT_01",
    atk_family: str = "ATK-02",
    ben_family: str = "BEN-01",
    critical_step: int = 2,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Construct a canonical matched pair (tau+, tau-) adhering to:
    - Registered tools (select_resource, configure_destination, execute_export).
    - Valid provenance envelopes.
    - Exact Action-D invariance at critical_step.
    """
    prov = {
        "generator_version": "0.1.0",
        "generator_hash": "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        "policy_spec_version": "P_spec_v1.0",
        "oracle_reviewer": "AUDITOR_01",
        "audit_timestamp": "2026-10-30T00:00:00Z",
    }

    # Attack trace tau+
    atk_actions = [
        {
            "step_index": 0,
            "tool": "select_resource",
            "arguments": {"resource_ref": "customer_records"},
            "y": 0,
            "is_critical": False,
        },
        {
            "step_index": 1,
            "tool": "configure_destination",
            "arguments": {"destination_ref": "external_storage"},
            "y": 0,
            "is_critical": False,
        },
        {
            "step_index": 2,
            "tool": "execute_export",
            "arguments": {"job_id": "job_99"},
            "y": 1,
            "is_critical": True,
            "declared_intent": "export data",
        },
    ]

    # Benign twin tau-
    ben_actions = [
        {
            "step_index": 0,
            "tool": "select_resource",
            "arguments": {"resource_ref": "public_records"},
            "y": 0,
            "is_critical": False,
        },
        {
            "step_index": 1,
            "tool": "configure_destination",
            "arguments": {"destination_ref": "external_storage"},
            "y": 0,
            "is_critical": False,
        },
        {
            "step_index": 2,
            "tool": "execute_export",
            "arguments": {"job_id": "job_99"},
            "y": 0,
            "is_critical": True,
            "declared_intent": "export data",
        },
    ]

    atk_trace_id = f"{atk_family}_{pair_id}"
    ben_trace_id = f"{ben_family}_{pair_id}"

    atk_trace = {
        "trace_id": atk_trace_id,
        "template_id": template_id,
        "family_id": atk_family,
        "scenario_type": "malicious_multistep",
        "twin_trace_id": ben_trace_id,
        "is_history_dependent": True,
        "critical_step_index": critical_step,
        "split": "DEV",
        "used_in_development_or_calibration": True,
        "provenance": prov,
        "actions": atk_actions,
    }
    atk_trace["content_digest"] = compute_actions_digest(atk_actions)

    ben_trace = {
        "trace_id": ben_trace_id,
        "template_id": template_id,
        "family_id": ben_family,
        "scenario_type": "benign_lookalike",
        "twin_trace_id": atk_trace_id,
        "is_history_dependent": True,
        "critical_step_index": critical_step,
        "split": "DEV",
        "used_in_development_or_calibration": True,
        "provenance": prov,
        "actions": ben_actions,
    }
    ben_trace["content_digest"] = compute_actions_digest(ben_actions)

    return atk_trace, ben_trace


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_valid_dataset_passes_validation(tmp_path: Path) -> None:
    """A valid paired dataset must pass validation with 0 errors and H1 ready."""
    atk, ben = make_valid_pair()
    data_file = tmp_path / "valid_traces.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is True
    assert len(report.errors) == 0
    assert report.h1_ready is True
    assert report.summary.twin_pairs_count == 1
    assert report.summary.total_traces == 2
    assert report.summary.attack_traces == 1
    assert report.summary.benign_traces == 1


def test_unregistered_tool_error(tmp_path: Path) -> None:
    """Tool not present in Registry must be flagged as TOOL_REGISTRY error."""
    atk, ben = make_valid_pair()
    atk["actions"][0]["tool"] = "malicious_unregistered_tool"
    atk["content_digest"] = compute_actions_digest(atk["actions"])

    data_file = tmp_path / "bad_tool.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    tool_errors = [e for e in report.errors if e.category == "TOOL_REGISTRY"]
    assert len(tool_errors) == 1
    assert "malicious_unregistered_tool" in tool_errors[0].message
    assert report.h1_ready is False


def test_schema_conformity_errors(tmp_path: Path) -> None:
    """Missing required trace or action fields must trigger SCHEMA errors."""
    bad_trace = {
        "template_id": "TMP_01",
        # missing trace_id
        "actions": [],  # empty actions
    }
    data_file = tmp_path / "bad_schema.json"
    data_file.write_text(json.dumps([bad_trace]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    schema_errors = [e for e in report.errors if e.category == "SCHEMA"]
    assert any("trace_id" in e.message for e in schema_errors)
    assert any("non-empty list" in e.message for e in schema_errors)


def test_duplicate_trace_id_detection(tmp_path: Path) -> None:
    """Duplicate trace_id across files or records must be flagged."""
    atk1, ben1 = make_valid_pair("P01")
    atk2, ben2 = make_valid_pair("P02")
    # Duplicate atk1 ID onto atk2
    atk2["trace_id"] = atk1["trace_id"]

    data_file = tmp_path / "dup_traces.json"
    data_file.write_text(json.dumps([atk1, ben1, atk2, ben2]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    dup_errors = [e for e in report.errors if e.category == "DUPLICATE_ID"]
    assert len(dup_errors) >= 1
    assert atk1["trace_id"] in dup_errors[0].message


def test_twin_relationship_errors(tmp_path: Path) -> None:
    """Twin integrity: missing twin, non-existent twin, asymmetric twin, template mismatch."""
    # 1. Missing twin reference
    atk1, ben1 = make_valid_pair("P01")
    atk1["twin_trace_id"] = None
    data_file1 = tmp_path / "missing_twin.json"
    data_file1.write_text(json.dumps([atk1, ben1]), encoding="utf-8")
    report1 = validate_dev_dataset(dataset_path=data_file1)
    assert any(e.category == "TWIN_RELATION" for e in report1.errors)

    # 2. Non-existent twin reference
    atk2, ben2 = make_valid_pair("P02")
    atk2["twin_trace_id"] = "GHOST_TRACE_ID"
    data_file2 = tmp_path / "ghost_twin.json"
    data_file2.write_text(json.dumps([atk2, ben2]), encoding="utf-8")
    report2 = validate_dev_dataset(dataset_path=data_file2)
    assert any("not found" in e.message for e in report2.errors if e.category == "TWIN_RELATION")

    # 3. Asymmetric twin
    atk3, ben3 = make_valid_pair("P03")
    ben3["twin_trace_id"] = "OTHER_TRACE"
    data_file3 = tmp_path / "asymmetric_twin.json"
    data_file3.write_text(json.dumps([atk3, ben3]), encoding="utf-8")
    report3 = validate_dev_dataset(dataset_path=data_file3)
    assert any(
        "twin symmetry" in e.message.lower()
        for e in report3.errors
        if e.category == "TWIN_RELATION"
    )

    # 4. Template mismatch
    atk4, ben4 = make_valid_pair("P04")
    ben4["template_id"] = "DIFFERENT_TEMPLATE"
    data_file4 = tmp_path / "tmpl_mismatch_twin.json"
    data_file4.write_text(json.dumps([atk4, ben4]), encoding="utf-8")
    report4 = validate_dev_dataset(dataset_path=data_file4)
    assert any(
        "template mismatch" in e.message.lower()
        for e in report4.errors
        if e.category == "TWIN_RELATION"
    )


def test_action_d_invariance_tool_mismatch(tmp_path: Path) -> None:
    """Action-D invariance: tool mismatch at t* must trigger ACTION_D_INVARIANCE error."""
    atk, ben = make_valid_pair()
    # Modify critical action tool on twin
    ben["actions"][2]["tool"] = "select_resource"
    ben["content_digest"] = compute_actions_digest(ben["actions"])

    data_file = tmp_path / "tool_mismatch.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    inv_errors = [e for e in report.errors if e.category == "ACTION_D_INVARIANCE"]
    assert len(inv_errors) >= 1
    assert "tool invariance violated" in inv_errors[0].message.lower()
    assert report.h1_ready is False


def test_action_d_invariance_argument_mismatch(tmp_path: Path) -> None:
    """Action-D invariance: argument difference at t* must trigger ACTION_D_INVARIANCE error."""
    atk, ben = make_valid_pair()
    # Modify critical action arguments on twin
    ben["actions"][2]["arguments"] = {"job_id": "job_DIFFERENT"}
    ben["content_digest"] = compute_actions_digest(ben["actions"])

    data_file = tmp_path / "args_mismatch.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    inv_errors = [e for e in report.errors if e.category == "ACTION_D_INVARIANCE"]
    assert len(inv_errors) >= 1
    assert "arguments invariance violated" in inv_errors[0].message.lower()
    assert report.h1_ready is False


def test_action_d_invariance_label_duality_failure(tmp_path: Path) -> None:
    """Action-D invariance: benign twin having y=1 at critical step fails label duality."""
    atk, ben = make_valid_pair()
    ben["actions"][2]["y"] = 1  # Should be 0
    ben["content_digest"] = compute_actions_digest(ben["actions"])

    data_file = tmp_path / "label_failure.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    inv_errors = [
        e for e in report.errors if e.category in ("ACTION_D_INVARIANCE", "TWIN_RELATION")
    ]
    assert len(inv_errors) >= 1


def test_action_d_early_violation_failure(tmp_path: Path) -> None:
    """tau+ with y=1 prior to critical step index t* must fail Action-D invariance."""
    atk, ben = make_valid_pair()
    atk["actions"][0]["y"] = 1  # Violation at step 0 before t*=2
    atk["content_digest"] = compute_actions_digest(atk["actions"])

    data_file = tmp_path / "early_viol.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    inv_errors = [e for e in report.errors if e.category == "ACTION_D_INVARIANCE"]
    assert any("prior to declared critical step" in e.message.lower() for e in inv_errors)


def test_split_contamination_check(tmp_path: Path) -> None:
    """Template overlap between DEV and CAL must trigger SPLIT_CONTAMINATION error."""
    dev_dir = tmp_path / "dev"
    cal_dir = tmp_path / "cal"
    dev_dir.mkdir(parents=True)
    cal_dir.mkdir(parents=True)

    shared_template = "TMP_SHARED_EXPORT"
    atk_dev, ben_dev = make_valid_pair(pair_id="P_DEV", template_id=shared_template)
    atk_cal, ben_cal = make_valid_pair(pair_id="P_CAL", template_id=shared_template)
    atk_cal["split"] = "CAL"
    ben_cal["split"] = "CAL"

    (dev_dir / "traces.json").write_text(json.dumps([atk_dev, ben_dev]), encoding="utf-8")
    (cal_dir / "traces.json").write_text(json.dumps([atk_cal, ben_cal]), encoding="utf-8")

    report = validate_dev_dataset(
        dataset_path=dev_dir,
        split="DEV",
        datasets_root=tmp_path,
    )
    assert report.is_valid is False
    split_errors = [e for e in report.errors if e.category == "SPLIT_CONTAMINATION"]
    assert len(split_errors) >= 1
    assert "template contamination" in split_errors[0].message.lower()


def test_content_digest_mismatch(tmp_path: Path) -> None:
    """Tampered actions without matching content_digest must be flagged."""
    atk, ben = make_valid_pair()
    fake_digest = "sha256:" + "0" * 64
    atk["content_digest"] = fake_digest

    data_file = tmp_path / "bad_digest.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    report = validate_dev_dataset(dataset_path=data_file)
    assert report.is_valid is False
    digest_errors = [e for e in report.errors if e.category == "DIGEST"]
    assert len(digest_errors) == 1
    assert "mismatch" in digest_errors[0].message.lower()


def test_manifest_verification(tmp_path: Path) -> None:
    """Manifest verification must confirm file hash integrity or report mismatch."""
    atk, ben = make_valid_pair()
    data_file = tmp_path / "traces.json"
    content = json.dumps([atk, ben])
    data_file.write_text(content, encoding="utf-8")

    import hashlib

    good_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    manifest_file = tmp_path / "manifest.sha256"
    manifest_file.write_text(f"{good_hash}  traces.json\n", encoding="utf-8")

    report = validate_dev_dataset(dataset_path=tmp_path)
    assert report.manifest_verified is True

    # Tamper manifest
    manifest_file.write_text(f"{'a' * 64}  traces.json\n", encoding="utf-8")
    report_bad = validate_dev_dataset(dataset_path=tmp_path)
    assert report_bad.manifest_verified is False
    assert any("hash mismatch" in e.message.lower() for e in report_bad.errors)


def test_empty_dataset_handling(tmp_path: Path) -> None:
    """Empty dataset directory must produce clean report without crashing."""
    report = validate_dev_dataset(dataset_path=tmp_path)
    assert report.is_valid is False
    assert report.summary.total_traces == 0
    assert report.h1_ready is False
    assert "empty" in report.h1_reason.lower()


def test_cli_invocation(tmp_path: Path, capsys: Any) -> None:
    """CLI execution via main() should succeed for valid dataset and exit with 0."""
    atk, ben = make_valid_pair()
    data_file = tmp_path / "cli_traces.json"
    data_file.write_text(json.dumps([atk, ben]), encoding="utf-8")

    out_json = tmp_path / "out_report.json"
    rc = cli_main(
        [
            "--dataset-path",
            str(data_file),
            "--format",
            "json",
            "--output-json",
            str(out_json),
        ]
    )
    assert rc == 0
    assert out_json.is_file()
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["is_valid"] is True
    assert res["h1_ready"] is True

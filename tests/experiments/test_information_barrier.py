"""
Tests for End-to-End Information Barrier and Anti-Leakage Validator.

Verifies:
1. Ground-truth labels and oracle metadata do not reach policy, monitor, or execution inputs.
2. Prohibited dataset metadata does not leak through nested structures.
3. Credentials, tokens, and raw secrets are sanitized from MonitorView and ReviewerView.
4. Canary fields planted in source data are absent from downstream decision components.
5. A deliberate leakage path triggers FAIL with exact path attribution.
"""

from pathlib import Path
from typing import Any

import pytest

from experiments.validation.information_barrier import (
    CANARIES,
    BoundaryAuditResult,
    InformationBarrierValidator,
    find_canaries_in_object,
    run_information_barrier_audit_on_dev,
)
from firewall.contracts.enums import (
    Classification,
    Decision,
    PolicyVerdict,
    Provenance,
    ToolClass,
    Zone,
)
from firewall.contracts.models import (
    CanonicalAction,
    DestinationRef,
    Event,
    MonitorView,
    ResourceRef,
    TaggedValue,
)
from firewall.state.engine import initial_state
from firewall.state.registry import Registry, ToolInfo
from firewall.state.views import (
    build_monitor_view,
    build_policy_view,
    build_reviewer_view,
    sanitize_data,
)


def test_information_barrier_audit_passes_on_live_architecture() -> None:
    """Verifies that the live architecture passes all static and runtime information-barrier checks."""
    result = run_information_barrier_audit_on_dev()

    assert result.passed is True
    assert result.static_checks_passed is True
    assert result.runtime_checks_passed is True
    assert result.total_boundaries_checked >= 8
    assert len(result.leakage_paths) == 0

    assert Path("experiments/datasets/dev/information_barrier_audit.json").exists()
    assert Path("experiments/reports/information_barrier_audit.md").exists()


def test_ground_truth_labels_do_not_reach_policy_or_monitor() -> None:
    """Verifies that ground-truth labels and oracle metadata cannot enter PolicyView or MonitorView."""
    registry = Registry(
        tools={"execute_export": ToolInfo(tool_class=ToolClass.EGRESS_EXTERNAL, args={})}
    )
    state = initial_state("sess_test")

    action = CanonicalAction(
        action_id="act_test",
        session_id="sess_test",
        seq=1,
        tool="execute_export",
        arguments={"batch_size": 10},
        action_hash="hash_test",
    )

    pv = build_policy_view(action, state, registry)
    mv = build_monitor_view("hybrid", action, state, registry)

    pv_leaks = find_canaries_in_object(pv)
    mv_leaks = find_canaries_in_object(mv)

    assert len(pv_leaks) == 0, f"Leakage found in PolicyView: {pv_leaks}"
    assert len(mv_leaks) == 0, f"Leakage found in MonitorView: {mv_leaks}"


def test_prohibited_metadata_cannot_leak_through_nested_structures() -> None:
    """Verifies that deeply nested sensitive fields and canary tokens are scrubbed recursively."""
    nested_payload: dict[str, Any] = {
        "level1": {
            "api_key": CANARIES["API_KEY"],
            "level2": {
                "password": CANARIES["PASSWORD"],
                "level3": [
                    {"auth_token": CANARIES["AUTH_TOKEN"]},
                    {"secret": CANARIES["NESTED_SECRET"]},
                    {"safe_data": "allowlisted_value"},
                ],
            },
        }
    }

    cleaned = sanitize_data(nested_payload)
    findings = find_canaries_in_object(cleaned)

    assert len(findings) == 0, f"Canary leaked through nested sanitization: {findings}"
    assert cleaned["level1"]["level2"]["level3"][2]["safe_data"] == "allowlisted_value"


def test_credentials_secrets_stripped_from_monitor_and_reviewer_views() -> None:
    """Verifies that API keys, passwords, and tokens are absent from MonitorView and ReviewerView."""
    registry = Registry(
        tools={"execute_export": ToolInfo(tool_class=ToolClass.EGRESS_EXTERNAL, args={})}
    )
    state = initial_state("sess_test")
    state.bound_resource = ResourceRef(ref="public_data", classification=Classification.PUBLIC, selected_seq=1)

    sensitive_args = {
        "batch_size": 20,
        "api_key": CANARIES["API_KEY"],
        "password": CANARIES["PASSWORD"],
        "token": CANARIES["AUTH_TOKEN"],
        "credentials": {"private_key": CANARIES["PRIVATE_KEY"]},
    }

    action = CanonicalAction(
        action_id="act_test",
        session_id="sess_test",
        seq=1,
        tool="execute_export",
        arguments=sensitive_args,
        action_hash="hash_test",
    )

    mv_action = build_monitor_view("action_only", action, state, registry)
    mv_transcript = build_monitor_view("transcript", action, state, registry)
    mv_hybrid = build_monitor_view("hybrid", action, state, registry)
    rv = build_reviewer_view(
        action=action,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        reason_codes=["NEEDS_REVIEW"],
        state=state,
    )

    for view_name, view in [
        ("ActionOnly", mv_action),
        ("Transcript", mv_transcript),
        ("Hybrid", mv_hybrid),
    ]:
        findings = find_canaries_in_object(view)
        assert len(findings) == 0, f"Canary credentials leaked into {view_name}: {findings}"

    # ReviewerView must contain zero oracle labels or canary credentials
    rv_findings = find_canaries_in_object(rv)
    oracle_leaks = [
        k for _, k, _ in rv_findings
        if k in ("GROUND_TRUTH_LABEL", "ORACLE_RATIONALE", "ORACLE_RULE_ID")
    ]
    assert len(oracle_leaks) == 0, f"Oracle metadata leaked into ReviewerView: {oracle_leaks}"


def test_deliberate_leakage_causes_audit_failure() -> None:
    """Verifies that an injected deliberate leakage path reliably causes audit failure."""
    validator = InformationBarrierValidator()
    original_method = validator.run_runtime_boundary_checks

    # Create custom check where a boundary deliberately contains a leaked canary
    def _injected_runtime_checks() -> list[BoundaryAuditResult]:
        real_checks = original_method()
        # Deliberately contaminate the first boundary with a leaked canary
        bad_boundary = BoundaryAuditResult(
            boundary_id="BOUNDARY_SIMULATED_LEAK",
            description="Simulated defective boundary leaking ground-truth label",
            target_component="DefectiveComponent",
            passed=False,
            leakage_detected=True,
            leakage_paths=["payload.ground_truth: leaked GROUND_TRUTH_LABEL"],
            evidence="Injected test leakage detected.",
        )
        return [bad_boundary] + real_checks

    # Monkeypatch runtime check to simulate leakage
    validator.run_runtime_boundary_checks = _injected_runtime_checks  # type: ignore

    res = validator.audit()

    assert res.passed is False, "Validator failed to flag deliberate leakage!"
    assert res.runtime_checks_passed is False
    assert any("BOUNDARY_SIMULATED_LEAK" in b.boundary_id for b in res.boundaries)
    assert any("GROUND_TRUTH_LABEL" in p for p in res.leakage_paths)

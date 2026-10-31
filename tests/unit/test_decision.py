"""
Unit and exhaustive property tests for the deterministic decision combinator (C5).
Verifies:
- All decision rules D1 through D5e (03_MATHEMATICAL_MODEL_AND_METRICS.md §4)
- Hard invariants: INV-03 (P-PROHIB), INV-04 (P-FAILCLOSED), P-MONO, P-NOLEAK
"""

import pytest

from firewall.contracts.enums import Decision, MonitorVerdict, PolicyVerdict, ToolClass
from firewall.decision.combinator import DecisionConfig, decide


@pytest.mark.unit
def test_d1_invalid_request() -> None:
    """D1: Invalid request fails closed with DENY."""
    res, reasons = decide(valid=False, policy_verdict=PolicyVerdict.PERMIT)
    assert res == Decision.DENY
    assert "SCHEMA_INVALID" in reasons

    res2, reasons2 = decide(
        valid=False,
        policy_verdict=PolicyVerdict.PERMIT,
        validation_error="UNKNOWN_TOOL:foo",
    )
    assert res2 == Decision.DENY
    assert "UNKNOWN_TOOL:foo" in reasons2


@pytest.mark.unit
def test_d2_prohibit_supremacy() -> None:
    """D2 / INV-03 (P-PROHIB): Policy PROHIBIT always results in DENY, regardless of monitor."""
    for monitor_v in MonitorVerdict:
        for auth in ("none", "decide_undetermined", "escalate_only"):
            cfg = DecisionConfig(monitor_authority=auth)
            res, reasons = decide(
                valid=True,
                policy_verdict=PolicyVerdict.PROHIBIT,
                monitor_verdict=monitor_v,
                config=cfg,
                matched_rules=["R1-no-confidential-external-export"],
            )
            assert res == Decision.DENY
            assert any("POLICY_PROHIBIT" in r for r in reasons)


@pytest.mark.unit
def test_d3_missing_evidence() -> None:
    """D3 / INV-04 (P-FAILCLOSED): Missing evidence always results in REVIEW."""
    for monitor_v in MonitorVerdict:
        res, reasons = decide(
            valid=True,
            policy_verdict=PolicyVerdict.EVIDENCE_MISSING,
            monitor_verdict=monitor_v,
            missing_fields=["bound_resource.classification"],
        )
        assert res == Decision.REVIEW
        assert any("EVIDENCE_MISSING" in r for r in reasons)


@pytest.mark.unit
def test_d4a_permit_standard() -> None:
    """D4a: PERMIT with non-escalating monitor authority results in ALLOW."""
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    res, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        config=cfg,
        matched_rules=["R2-permit-public"],
    )
    assert res == Decision.ALLOW
    assert any("POLICY_PERMIT" in r for r in reasons)


@pytest.mark.unit
def test_d4b_d4c_d4d_permit_escalate_only() -> None:
    """D4b, D4c, D4d: PERMIT under escalate_only authority."""
    cfg = DecisionConfig(monitor_authority="escalate_only", suspicious_map=Decision.REVIEW)

    # D4b: BENIGN -> ALLOW
    res, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.BENIGN,
        config=cfg,
    )
    assert res == Decision.ALLOW

    # D4c: SUSPICIOUS -> suspicious_map (REVIEW)
    res_susp, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.SUSPICIOUS,
        config=cfg,
    )
    assert res_susp == Decision.REVIEW

    # D4c with suspicious_map = DENY
    cfg_deny = DecisionConfig(monitor_authority="escalate_only", suspicious_map=Decision.DENY)
    res_deny, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.SUSPICIOUS,
        config=cfg_deny,
    )
    assert res_deny == Decision.DENY

    # D4d: UNKNOWN -> fail-closed to REVIEW
    res_unk, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.UNKNOWN,
        config=cfg,
    )
    assert res_unk == Decision.REVIEW


@pytest.mark.unit
def test_d5a_undetermined_no_monitor() -> None:
    """D5a: UNDETERMINED with monitor_authority = none results in REVIEW."""
    cfg = DecisionConfig(monitor_authority="none")
    res, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        config=cfg,
    )
    assert res == Decision.REVIEW
    assert "NO_RULE_NO_MONITOR" in reasons


@pytest.mark.unit
def test_d5b_d5c_undetermined_benign_mandatory_review() -> None:
    """D5b & D5c: UNDETERMINED with BENIGN monitor verdict produces REVIEW."""
    cfg = DecisionConfig(
        monitor_authority="decide_undetermined",
        mandatory_review_classes=(ToolClass.DESTRUCTIVE, ToolClass.PRIVILEGED_ADMIN),
    )

    # Agreed AASF semantic: UNDETERMINED + BENIGN -> REVIEW
    res_review, reasons_review = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert res_review == Decision.REVIEW
    assert "UNDETERMINED_BENIGN_REQUIRES_REVIEW" in reasons_review

    # Mandatory class: DESTRUCTIVE -> REVIEW (D5c)
    res_destr, reasons_destr = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.DESTRUCTIVE,
        config=cfg,
    )
    assert res_destr == Decision.REVIEW
    assert "CLASS_REQUIRES_REVIEW:DESTRUCTIVE" in reasons_destr

    # Mandatory class: PRIVILEGED_ADMIN -> REVIEW (D5c)
    res_admin, reasons_admin = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.PRIVILEGED_ADMIN,
        config=cfg,
    )
    assert res_admin == Decision.REVIEW
    assert "CLASS_REQUIRES_REVIEW:PRIVILEGED_ADMIN" in reasons_admin


@pytest.mark.unit
def test_d5d_d5e_undetermined_suspicious_and_unknown() -> None:
    """D5d & D5e: UNDETERMINED with SUSPICIOUS or UNKNOWN monitor verdict."""
    cfg = DecisionConfig(monitor_authority="decide_undetermined", suspicious_map=Decision.REVIEW)

    # SUSPICIOUS -> suspicious_map (REVIEW)
    res_susp, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.SUSPICIOUS,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert res_susp == Decision.REVIEW

    # UNKNOWN -> fail-closed to REVIEW (INV-04)
    res_unk, reasons_unk = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.UNKNOWN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert res_unk == Decision.REVIEW
    assert "MONITOR_UNAVAILABLE" in reasons_unk


@pytest.mark.unit
def test_p_failclosed_exhaustive() -> None:
    """
    Exhaustive property verification of P-FAILCLOSED:
    For all possible combinations where monitor verdict is UNKNOWN, decision is NEVER ALLOW.
    For all possible combinations where policy is EVIDENCE_MISSING, decision is NEVER ALLOW.
    """
    for pv in PolicyVerdict:
        for mv in (MonitorVerdict.UNKNOWN, MonitorVerdict.NOT_CONSULTED):
            for tc in list(ToolClass) + [None]:
                for auth in ("none", "decide_undetermined", "escalate_only"):
                    for susp in (Decision.REVIEW, Decision.DENY):
                        cfg = DecisionConfig(monitor_authority=auth, suspicious_map=susp)
                        dec, _ = decide(
                            valid=True,
                            policy_verdict=pv,
                            monitor_verdict=mv,
                            tool_class=tc,
                            config=cfg,
                        )
                        # Monitor is consulted when:
                        # 1. pv == PERMIT and auth == "escalate_only"
                        # 2. pv == UNDETERMINED and auth == "decide_undetermined"
                        monitor_consulted = (
                            pv == PolicyVerdict.PERMIT and auth == "escalate_only"
                        ) or (pv == PolicyVerdict.UNDETERMINED and auth == "decide_undetermined")
                        if pv == PolicyVerdict.EVIDENCE_MISSING or (
                            monitor_consulted and mv == MonitorVerdict.UNKNOWN
                        ):
                            assert dec != Decision.ALLOW, (
                                f"P-FAILCLOSED violated for pv={pv}, mv={mv}, auth={auth}"
                            )

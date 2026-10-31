"""
Comprehensive regression test suite for AASF security semantics and advisory rejection cascade.
Enforces all 24 required test cases across:
- Cases 1-6: Adapter-level advisory mappings
- Cases 7-18: Core combinator and security invariants
- Cases 19-21: MonitorView isolation and sensitive field sanitization
- Cases 22-24: Review approval state and policy freshness revalidation
"""

from unittest.mock import MagicMock

import pytest

from firewall.cascade.adapter import (
    AdvisoryVerdict,
    CascadeAdapter,
    CascadeFailureReason,
    MonitorAdvisory,
)
from firewall.contracts.enums import (
    Classification,
    Decision,
    EventType,
    MonitorVerdict,
    PolicyVerdict,
    Provenance,
    ToolClass,
)
from firewall.contracts.models import (
    ActionRequest,
    CanonicalAction,
    Event,
    MonitorAssessment,
    ResourceRef,
    StateEventEnvelope,
    TaggedValue,
)
from firewall.core import FirewallCore
from firewall.decision.combinator import DecisionConfig, decide
from firewall.state.engine import apply_event, initial_state
from firewall.state.registry import Registry
from firewall.state.views import build_monitor_view, format_transcript


@pytest.fixture
def test_registry() -> Registry:
    return Registry(
        resources={
            "customer_records": {"classification": "CONFIDENTIAL", "rows": 5000},
            "public_records": {"classification": "PUBLIC", "rows": 800},
            "other_records": {"classification": "PUBLIC", "rows": 500},
        },
        destinations={
            "external_storage": {"zone": "EXTERNAL"},
            "internal_archive": {"zone": "INTERNAL"},
        },
        tools={
            "select_resource": {"tool_class": "READ_SENSITIVE"},
            "create_export_job": {"tool_class": "WRITE_INTERNAL"},
            "configure_destination": {"tool_class": "WRITE_INTERNAL"},
            "execute_export": {"tool_class": "EGRESS_EXTERNAL"},
            "validate_schema": {"tool_class": "READ_LOW"},
            "delete_resource": {"tool_class": "DESTRUCTIVE"},
            "relabel_resource": {"tool_class": "PRIVILEGED_ADMIN"},
            "query_records": {"tool_class": "READ_SENSITIVE"},
        },
    )


# ==============================================================================
# Cases 1-6: Adapter-Level Advisory Mappings
# ==============================================================================


@pytest.mark.unit
def test_case_01_adapter_benign_maps_to_low_risk_not_allow() -> None:
    """Case 1: BENIGN maps to advisory LOW_RISK, not ALLOW."""
    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.BENIGN,
        rationale="Request appears benign",
        monitor_version="0.1.0",
    )
    adapter = CascadeAdapter(monitor=mock_mon)

    res = adapter.decide(
        policy_verdict=PolicyVerdict.UNDETERMINED,
        action={"tool": "query_records", "arguments": {}},
    )

    assert isinstance(res, MonitorAdvisory)
    assert res.verdict == AdvisoryVerdict.LOW_RISK.value
    assert res.monitor_verdict == MonitorVerdict.BENIGN
    assert res.decision is None
    # Must NOT equal or map to Decision.ALLOW
    assert res != Decision.ALLOW
    assert res.verdict != Decision.ALLOW


@pytest.mark.unit
def test_case_02_adapter_suspicious_maps_to_elevated_risk_not_deny() -> None:
    """Case 2: SUSPICIOUS maps to advisory ELEVATED_RISK, not DENY."""
    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.SUSPICIOUS,
        rationale="Anomalous behavior observed",
        monitor_version="0.1.0",
    )
    adapter = CascadeAdapter(monitor=mock_mon)

    res = adapter.decide(
        policy_verdict=PolicyVerdict.UNDETERMINED,
        action={"tool": "query_records", "arguments": {}},
    )

    assert isinstance(res, MonitorAdvisory)
    assert res.verdict == AdvisoryVerdict.ELEVATED_RISK.value
    assert res.monitor_verdict == MonitorVerdict.SUSPICIOUS
    assert res.decision is None
    # Must NOT equal or map to Decision.DENY
    assert res != Decision.DENY
    assert res.verdict != Decision.DENY


@pytest.mark.unit
def test_case_03_adapter_unknown_maps_to_uncertain() -> None:
    """Case 3: UNKNOWN maps to advisory UNCERTAIN."""
    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.UNKNOWN,
        rationale="Insufficient model confidence",
        monitor_version="0.1.0",
    )
    adapter = CascadeAdapter(monitor=mock_mon)

    res = adapter.decide(
        policy_verdict=PolicyVerdict.UNDETERMINED,
        action={"tool": "query_records", "arguments": {}},
    )

    assert res.verdict == AdvisoryVerdict.UNCERTAIN.value
    assert res.monitor_verdict == MonitorVerdict.UNKNOWN
    assert res.recommended_outcome == "REVIEW"
    assert res.decision is None


@pytest.mark.unit
def test_case_04_adapter_malformed_json_maps_to_unavailable_review() -> None:
    """Case 4: Malformed JSON maps to advisory UNAVAILABLE / escalate to REVIEW."""
    mock_mon = MagicMock(return_value="INVALID_JSON{{not_json")
    adapter = CascadeAdapter(monitor=mock_mon)

    res = adapter.decide(
        policy_verdict=PolicyVerdict.UNDETERMINED,
        action={"tool": "query_records", "arguments": {}},
    )

    assert res.verdict == AdvisoryVerdict.UNAVAILABLE.value
    assert res.recommended_outcome == "REVIEW"
    assert res.monitor_verdict == MonitorVerdict.UNKNOWN
    assert CascadeFailureReason.MALFORMED_OUTPUT.value in res.reason_codes
    assert res.decision is None


@pytest.mark.unit
def test_case_05_adapter_timeout_maps_to_unavailable_review() -> None:
    """Case 5: Timeout maps to advisory UNAVAILABLE / escalate to REVIEW."""
    mock_mon = MagicMock(side_effect=TimeoutError("Monitor latency exceeded threshold"))
    adapter = CascadeAdapter(monitor=mock_mon)

    res = adapter.decide(
        policy_verdict=PolicyVerdict.UNDETERMINED,
        action={"tool": "query_records", "arguments": {}},
    )

    assert res.verdict == AdvisoryVerdict.UNAVAILABLE.value
    assert res.recommended_outcome == "REVIEW"
    assert res.monitor_verdict == MonitorVerdict.UNKNOWN
    assert CascadeFailureReason.MONITOR_TIMEOUT.value in res.reason_codes
    assert res.decision is None


@pytest.mark.unit
def test_case_06_adapter_exception_maps_to_unavailable_review() -> None:
    """Case 6: Exception maps to advisory UNAVAILABLE / escalate to REVIEW."""
    mock_mon = MagicMock(side_effect=RuntimeError("Internal inference failure"))
    adapter = CascadeAdapter(monitor=mock_mon)

    res = adapter.decide(
        policy_verdict=PolicyVerdict.UNDETERMINED,
        action={"tool": "query_records", "arguments": {}},
    )

    assert res.verdict == AdvisoryVerdict.UNAVAILABLE.value
    assert res.recommended_outcome == "REVIEW"
    assert res.monitor_verdict == MonitorVerdict.UNKNOWN
    assert CascadeFailureReason.MONITOR_EXCEPTION.value in res.reason_codes
    assert res.decision is None


# ==============================================================================
# Cases 7-18: Core Combinator and Security Invariants
# ==============================================================================


@pytest.mark.unit
def test_case_07_undetermined_plus_benign_equals_review_never_allow(
    test_registry: Registry,
) -> None:
    """Case 7: UNDETERMINED + BENIGN = REVIEW, never ALLOW or execution."""
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    dec, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.UNDETERMINED,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert dec == Decision.REVIEW
    assert "UNDETERMINED_BENIGN_REQUIRES_REVIEW" in reasons

    # In FirewallCore
    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.BENIGN,
        rationale="Benign monitor output",
        monitor_version="0.1.0",
    )
    adapter = CascadeAdapter(monitor=mock_mon)
    fw = FirewallCore(registry=test_registry, cascade_adapter=adapter)

    resp = fw.submit(
        ActionRequest(
            session_id="sess_c7",
            tool="query_records",
            arguments={},
        )
    )
    # query_records is UNDETERMINED under default policy rules
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"
    assert resp.ticket_id is not None
    assert resp.result is None


@pytest.mark.unit
def test_case_08_prohibit_plus_benign_equals_deny(test_registry: Registry) -> None:
    """Case 8: PROHIBIT + BENIGN = DENY."""
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    dec, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PROHIBIT,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
        matched_rules=["R1-no-confidential-external-export"],
    )
    assert dec == Decision.DENY
    assert any("POLICY_PROHIBIT" in r for r in reasons)

    # In FirewallCore
    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.BENIGN,
        rationale="Benign",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon)
    session_id = "sess_c8"
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="select_resource",
            arguments={"resource_ref": "customer_records"},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )
    # Binding confidential resource and external storage makes execute_export PROHIBIT under R1
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.decision == Decision.DENY
    assert resp.status == "DENIED"


@pytest.mark.unit
def test_case_09_prohibit_plus_suspicious_equals_deny(test_registry: Registry) -> None:
    """Case 9: PROHIBIT + SUSPICIOUS = DENY."""
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    dec, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PROHIBIT,
        monitor_verdict=MonitorVerdict.SUSPICIOUS,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
        matched_rules=["R1"],
    )
    assert dec == Decision.DENY

    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.SUSPICIOUS,
        rationale="Suspicious",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon)
    session_id = "sess_c9"
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="select_resource",
            arguments={"resource_ref": "customer_records"},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.decision == Decision.DENY
    assert resp.status == "DENIED"


@pytest.mark.unit
def test_case_10_prohibit_plus_unknown_equals_deny(test_registry: Registry) -> None:
    """Case 10: PROHIBIT + UNKNOWN = DENY."""
    cfg = DecisionConfig(monitor_authority="decide_undetermined")
    dec, _ = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PROHIBIT,
        monitor_verdict=MonitorVerdict.UNKNOWN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
        matched_rules=["R1"],
    )
    assert dec == Decision.DENY

    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.UNKNOWN,
        rationale="Unknown",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon)
    session_id = "sess_c10"
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="select_resource",
            arguments={"resource_ref": "customer_records"},
        )
    )
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.decision == Decision.DENY
    assert resp.status == "DENIED"


@pytest.mark.unit
def test_case_11_prohibit_plus_malformed_timeout_exception_equals_deny(
    test_registry: Registry,
) -> None:
    """Case 11: PROHIBIT + malformed/timeout/exception = DENY."""
    for exc in [TimeoutError("Timeout"), RuntimeError("Crash"), ValueError("Malformed")]:
        mock_mon = MagicMock(side_effect=exc)
        fw = FirewallCore(registry=test_registry, monitor=mock_mon)
        session_id = f"sess_c11_{type(exc).__name__}"
        fw.submit(
            ActionRequest(
                session_id=session_id,
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            )
        )
        fw.submit(
            ActionRequest(
                session_id=session_id,
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
        assert resp.decision == Decision.DENY
        assert resp.status == "DENIED"


@pytest.mark.unit
def test_case_12_allow_plus_suspicious_elevated_risk_equals_review(test_registry: Registry) -> None:
    """Case 12: Policy PERMIT + SUSPICIOUS/ELEVATED_RISK = REVIEW."""
    cfg = DecisionConfig(monitor_authority="escalate_only", suspicious_map=Decision.REVIEW)
    dec, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.SUSPICIOUS,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert dec == Decision.REVIEW
    assert "MONITOR_ESCALATION" in reasons

    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.SUSPICIOUS,
        rationale="High risk",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon, decision_config=cfg)
    resp = fw.submit(
        ActionRequest(
            session_id="sess_c12",
            tool="validate_schema",
            arguments={},
        )
    )
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"


@pytest.mark.unit
def test_case_13_allow_plus_benign_low_risk_for_non_mandatory_tool_may_allow(
    test_registry: Registry,
) -> None:
    """Case 13: Policy PERMIT + BENIGN/LOW_RISK for non-mandatory tool may ALLOW
    only if all checks pass."""
    cfg = DecisionConfig(monitor_authority="escalate_only")
    dec, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.BENIGN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert dec == Decision.ALLOW
    assert any("POLICY_PERMIT" in r for r in reasons)

    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.BENIGN,
        rationale="All good",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon, decision_config=cfg)
    resp = fw.submit(
        ActionRequest(
            session_id="sess_c13",
            tool="validate_schema",
            arguments={},
        )
    )
    assert resp.decision == Decision.ALLOW
    assert resp.status == "EXECUTED"
    assert resp.result is not None
    assert resp.result.has_value is True


@pytest.mark.unit
def test_case_14_mandatory_review_tool_class_results_in_review_even_with_benign(
    test_registry: Registry,
) -> None:
    """Case 14: Mandatory-review tool class results in REVIEW even with BENIGN monitor output."""
    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.BENIGN,
        rationale="Safe",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon)

    resp = fw.submit(
        ActionRequest(
            session_id="sess_c14",
            tool="delete_resource",
            arguments={"resource_ref": "public_records"},
        )
    )
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"
    assert any("CLASS_REQUIRES_REVIEW" in r for r in resp.reason_codes)


@pytest.mark.unit
def test_case_15_unknown_monitor_output_results_in_review(test_registry: Registry) -> None:
    """Case 15: UNKNOWN monitor output results in REVIEW."""
    cfg = DecisionConfig(monitor_authority="escalate_only")
    dec, reasons = decide(
        valid=True,
        policy_verdict=PolicyVerdict.PERMIT,
        monitor_verdict=MonitorVerdict.UNKNOWN,
        tool_class=ToolClass.READ_LOW,
        config=cfg,
    )
    assert dec == Decision.REVIEW
    assert "MONITOR_UNAVAILABLE" in reasons

    mock_mon = MagicMock()
    mock_mon.assess.return_value = MonitorAssessment(
        verdict=MonitorVerdict.UNKNOWN,
        rationale="Uncertain",
        monitor_version="0.1.0",
    )
    fw = FirewallCore(registry=test_registry, monitor=mock_mon, decision_config=cfg)
    resp = fw.submit(
        ActionRequest(
            session_id="sess_c15",
            tool="validate_schema",
            arguments={},
        )
    )
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"


@pytest.mark.unit
def test_case_16_malformed_monitor_output_results_in_review(test_registry: Registry) -> None:
    """Case 16: Malformed monitor output results in REVIEW."""
    mock_mon = MagicMock(return_value="NOT_VALID_JSON{:::}")
    adapter = CascadeAdapter(monitor=mock_mon)
    fw = FirewallCore(registry=test_registry, cascade_adapter=adapter)

    resp = fw.submit(
        ActionRequest(
            session_id="sess_c16",
            tool="query_records",
            arguments={},
        )
    )
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"
    assert resp.ticket_id is not None


@pytest.mark.unit
def test_case_17_monitor_timeout_results_in_review(test_registry: Registry) -> None:
    """Case 17: Monitor timeout results in REVIEW."""
    mock_mon = MagicMock(side_effect=TimeoutError("Cascade timeout"))
    adapter = CascadeAdapter(monitor=mock_mon)
    fw = FirewallCore(registry=test_registry, cascade_adapter=adapter)

    resp = fw.submit(
        ActionRequest(
            session_id="sess_c17",
            tool="query_records",
            arguments={},
        )
    )
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"
    assert resp.ticket_id is not None


@pytest.mark.unit
def test_case_18_monitor_exception_results_in_review(test_registry: Registry) -> None:
    """Case 18: Monitor exception results in REVIEW."""
    mock_mon = MagicMock(side_effect=RuntimeError("Internal inference crash"))
    adapter = CascadeAdapter(monitor=mock_mon)
    fw = FirewallCore(registry=test_registry, cascade_adapter=adapter)

    resp = fw.submit(
        ActionRequest(
            session_id="sess_c18",
            tool="query_records",
            arguments={},
        )
    )
    assert resp.decision == Decision.REVIEW
    assert resp.status == "PENDING_REVIEW"
    assert resp.ticket_id is not None


# ==============================================================================
# Cases 19-21: MonitorView Isolation and Sanitization
# ==============================================================================


@pytest.mark.unit
def test_case_19_monitor_mutation_of_action_does_not_change_original_action(
    test_registry: Registry,
) -> None:
    """Case 19: Monitor attempt to mutate action object does not change original action."""
    original_action = CanonicalAction(
        action_id="act_iso_19",
        session_id="sess_iso_19",
        seq=1,
        tool="validate_schema",
        arguments={"input_data": {"key": "original_val"}},
        action_hash="hash_iso_19",
    )
    state = initial_state("sess_iso_19")

    view = build_monitor_view(
        monitor_type="hybrid",
        action=original_action,
        state=state,
        registry=test_registry,
    )

    # Malicious monitor attempts mutation on projection
    view.action.arguments["input_data"]["key"] = "tampered_by_monitor"
    view.action.arguments["injected_attack"] = True
    view.action.tool = "destructive_tool"

    # Original action must remain unchanged
    assert original_action.tool == "validate_schema"
    assert original_action.arguments["input_data"]["key"] == "original_val"
    assert "injected_attack" not in original_action.arguments


@pytest.mark.unit
def test_case_20_monitor_mutation_of_state_summary_does_not_change_original_state(
    test_registry: Registry,
) -> None:
    """Case 20: Monitor attempt to mutate state summary does not change original state."""
    state = initial_state("sess_iso_20").model_copy(
        update={
            "bound_resource": ResourceRef(
                ref="customer_records",
                classification=Classification.CONFIDENTIAL,
                selected_seq=1,
            ),
            "selected_resources": [
                ResourceRef(
                    ref="customer_records",
                    classification=Classification.CONFIDENTIAL,
                    selected_seq=1,
                )
            ],
        }
    )
    action = CanonicalAction(
        action_id="act_iso_20",
        session_id="sess_iso_20",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash="hash_iso_20",
    )

    view = build_monitor_view(
        monitor_type="Hybrid",
        action=action,
        state=state,
        registry=test_registry,
    )

    assert view.state_summary is not None
    # Malicious monitor mutates state summary dict
    view.state_summary["bound_resource"] = "tampered_resource"
    view.state_summary["selected_resources"].append("fake_resource")

    # Original session state must remain unchanged
    assert state.bound_resource is not None
    assert state.bound_resource.ref == "customer_records"
    assert len(state.selected_resources) == 1
    assert state.selected_resources[0].ref == "customer_records"


@pytest.mark.unit
def test_case_21_sensitive_fields_not_exposed_through_monitor_view(
    test_registry: Registry,
) -> None:
    """Case 21: Sensitive fields (tokens, passwords, keys) are not exposed through MonitorView."""
    action = CanonicalAction(
        action_id="act_iso_21",
        session_id="sess_iso_21",
        seq=1,
        tool="validate_schema",
        arguments={
            "api_key": "secret_api_key_999",
            "password": "super_secret_password",
            "auth_token": "token_abc_xyz",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "safe_param": "safe_value",
        },
        action_hash="hash_iso_21",
    )
    state = initial_state("sess_iso_21")

    view = build_monitor_view(
        monitor_type="hybrid",
        action=action,
        state=state,
        registry=test_registry,
    )

    # Sensitive keys must be scrubbed / stripped completely from monitor projection
    for secret_key in ["api_key", "password", "auth_token", "private_key"]:
        assert secret_key not in view.action.arguments
    assert view.action.arguments["safe_param"] == "safe_value"
    assert "secret_api_key_999" not in str(view.model_dump())
    assert "super_secret_password" not in str(view.model_dump())

    # Also verify transcript serialization does not expose raw values
    view_transcript = build_monitor_view(
        monitor_type="transcript",
        action=action,
        state=state,
        registry=test_registry,
    )
    if view_transcript.transcript:
        assert "secret_api_key_999" not in view_transcript.transcript
        assert "super_secret_password" not in view_transcript.transcript


# ==============================================================================
# Cases 22-24: Review Freshness and Policy Revalidation
# ==============================================================================


@pytest.mark.unit
def test_case_22_review_approval_cannot_execute_if_policy_becomes_prohibit(
    test_registry: Registry,
) -> None:
    """Case 22: Review approval cannot execute if policy becomes PROHIBIT."""
    fw = FirewallCore(registry=test_registry)
    session_id = "sess_c22"

    # Step 1: Configure external destination
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    # Step 2: execute_export without bound resource enters PENDING_REVIEW (EVIDENCE_MISSING)
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    # Step 3: State changes so CONFIDENTIAL resource is bound; export becomes PROHIBIT under R1
    s_curr = fw._get_state(session_id)
    env_bound = StateEventEnvelope(
        session_id=session_id,
        seq=s_curr.seq + 1,
        prior_head=s_curr.head_hash,
        event_type=EventType.EXECUTED.value,
        action_id="act_bind_conf",
        token_id="tok_bind_conf",
        payload={"tool": "select_resource", "arguments": {"resource_ref": "customer_records"}},
    )
    fw._states[session_id] = apply_event(
        s_curr, env_bound, fw.registry, expected_session_id=session_id
    )

    # Step 4: Approver attempts to approve the ticket
    resolve_resp = fw.resolve_review(
        ticket_id=ticket_id, outcome="APPROVE", reviewer_id="reviewer_1"
    )

    # Revalidation must prevent execution and return DENY
    assert resolve_resp.status != "EXECUTED"
    assert resolve_resp.decision == Decision.DENY
    assert any("POLICY_PROHIBIT" in r for r in resolve_resp.reason_codes)


@pytest.mark.unit
def test_case_23_review_approval_cannot_execute_if_state_head_changed(
    test_registry: Registry,
) -> None:
    """Case 23: Review approval cannot execute if state head changed."""
    fw = FirewallCore(registry=test_registry)
    session_id = "sess_c23"

    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    # State advances while review ticket is pending
    s_curr = fw._get_state(session_id)
    env_adv = StateEventEnvelope(
        session_id=session_id,
        seq=s_curr.seq + 1,
        prior_head=s_curr.head_hash,
        event_type=EventType.EXECUTED.value,
        action_id="act_adv",
        token_id="tok_adv",
        payload={"tool": "select_resource", "arguments": {"resource_ref": "other_records"}},
    )
    fw._states[session_id] = apply_event(
        s_curr, env_adv, fw.registry, expected_session_id=session_id
    )

    # Approver approves ticket
    resolve_resp = fw.resolve_review(
        ticket_id=ticket_id, outcome="APPROVE", reviewer_id="reviewer_2"
    )

    # Must detect stale state head and refuse execution
    assert resolve_resp.status != "EXECUTED"
    assert resolve_resp.decision == Decision.DENY
    assert any("STATE_CHANGED" in r for r in resolve_resp.reason_codes)


@pytest.mark.unit
def test_case_24_review_approval_can_execute_only_when_policy_and_state_remain_valid(
    test_registry: Registry,
) -> None:
    """Case 24: Review approval can execute only when policy and state remain valid."""
    fw = FirewallCore(registry=test_registry)
    session_id = "sess_c24"

    # Destination configured to external storage
    fw.submit(
        ActionRequest(
            session_id=session_id,
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        )
    )

    # execute_export with incomplete evidence creates a ticket (PENDING_REVIEW)
    resp = fw.submit(ActionRequest(session_id=session_id, tool="execute_export", arguments={}))
    assert resp.status == "PENDING_REVIEW"
    ticket_id = resp.ticket_id
    assert ticket_id is not None

    # State has NOT changed and policy is NOT PROHIBIT
    resolve_resp = fw.resolve_review(
        ticket_id=ticket_id, outcome="APPROVE", reviewer_id="reviewer_3"
    )

    # Ticket approval executes cleanly
    assert resolve_resp.status == "EXECUTED"
    assert resolve_resp.result is not None
    assert resolve_resp.result.has_value is True
    assert resolve_resp.result.error is None


# ==============================================================================
# Case 25: Information-Barrier Credential Scrubbing Verification
# ==============================================================================


@pytest.mark.unit
def test_case_25_synthetic_secrets_in_transcript_output_error_and_free_text_scrubbed(
    test_registry: Registry,
) -> None:
    """Case 25: Synthetic secrets planted in transcript output, free_text, error,
    and nested content cannot leak into monitor-visible representations."""
    planted_secrets = [
        "secret_token_live_12345",
        "ak_live_xyz987654321",
        "super_secret_db_pass",
        "cs_top_secret_key",
        "raw_secret_key_nested",
        "nested_pwd_val_999",
        "supersecret_token_in_envelope",
    ]

    events = [
        # Envelope with sensitive string in output and error
        StateEventEnvelope(
            session_id="sess_sec25",
            seq=1,
            prior_head="GENESIS",
            event_type=EventType.EXECUTED.value,
            action_id="act_sec25_1",
            token_id="tok_1",
            payload={
                "tool": "select_resource",
                "arguments": {"resource_ref": "customer_records"},
                "output": (
                    "Export finished with token=secret_token_live_12345 and "
                    "api_key=ak_live_xyz987654321"
                ),
                "error": (
                    "Connection error with password='super_secret_db_pass' and "
                    "client_secret=cs_top_secret_key"
                ),
            },
        ),
        # Envelope with nested dictionary secrets
        StateEventEnvelope(
            session_id="sess_sec25",
            seq=2,
            prior_head="h1",
            event_type=EventType.EXECUTED.value,
            action_id="act_sec25_2",
            token_id="tok_2",
            payload={
                "tool": "configure_destination",
                "arguments": {"destination_ref": "external_storage"},
                "free_text": (
                    "Agent user message Bearer "
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDN secretly"
                ),
                "output": {
                    "sensitive_dict": {
                        "api_key": "raw_secret_key_nested",
                        "nested": {"password": "nested_pwd_val_999"},
                    },
                    "safe_metric": 42,
                },
            },
        ),
        # Event with PEM private key in free_text and sensitive arguments
        Event(
            event_id="evt_sec25_3",
            session_id="sess_sec25",
            seq=3,
            type=EventType.EXECUTED.value,
            action_id="act_sec25_3",
            fields={
                "tool": TaggedValue(
                    value="validate_schema",
                    provenance=Provenance.TOOL_TYPED,
                ),
                "arguments": TaggedValue(
                    value={"auth_token": "supersecret_token_in_envelope", "safe_field": "ok"},
                    provenance=Provenance.TOOL_TYPED,
                ),
            },
            free_text=(
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA0...\n"
                "-----END RSA PRIVATE KEY-----"
            ),
        ),
    ]

    # 1. format_transcript direct audit
    formatted = format_transcript(events)
    for secret in planted_secrets:
        assert secret not in formatted, f"Secret {secret} leaked into format_transcript output!"
    assert "-----BEGIN RSA PRIVATE KEY-----" not in formatted

    # Preserved safe data
    assert "customer_records" in formatted
    assert "external_storage" in formatted
    assert "safe_metric" in formatted
    assert "42" in formatted

    # 2. build_monitor_view projection audit
    action = CanonicalAction(
        action_id="act_sec25_cur",
        session_id="sess_sec25",
        seq=4,
        tool="execute_export",
        arguments={"safe_arg": "public_data"},
        action_hash="hash_sec25",
    )
    state = initial_state("sess_sec25")

    # Transcript monitor view
    view_t = build_monitor_view(
        monitor_type="transcript",
        action=action,
        state=state,
        registry=test_registry,
        history=events,
    )
    assert view_t.transcript is not None
    view_dump_str = str(view_t.model_dump())
    for secret in planted_secrets:
        assert secret not in view_t.transcript, f"Secret {secret} leaked into view.transcript!"
        assert secret not in view_dump_str, f"Secret {secret} leaked into view model_dump!"
    assert "-----BEGIN RSA PRIVATE KEY-----" not in view_t.transcript
    assert "-----BEGIN RSA PRIVATE KEY-----" not in view_dump_str

    # Hybrid monitor view
    view_h = build_monitor_view(
        monitor_type="hybrid",
        action=action,
        state=state,
        registry=test_registry,
        history=events,
    )
    view_h_str = str(view_h.model_dump())
    for secret in planted_secrets:
        assert secret not in view_h_str, f"Secret {secret} leaked into hybrid view!"
    assert "-----BEGIN RSA PRIVATE KEY-----" not in view_h_str

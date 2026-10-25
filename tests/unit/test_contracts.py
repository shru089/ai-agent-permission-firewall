"""
Unit tests for shared Pydantic contracts (v0.1.0).
Source: 05_TECHNICAL_SPEC.md §3, 08_IMPLEMENTATION_ROADMAP.md Phase 1
"""

import pytest
from pydantic import ValidationError

from firewall.contracts import (
    CONTRACTS_VERSION,
    ActionRequest,
    CanonicalAction,
    Classification,
    ConfirmationLevel,
    Decision,
    DecisionRecord,
    DestinationRef,
    EgressCounter,
    EventType,
    EvidenceReceipt,
    ExecStatus,
    MonitorVerdict,
    OutcomeContract,
    PolicyVerdict,
    Provenance,
    ResourceRef,
    ResultEnvelope,
    ReviewerView,
    ReviewStatus,
    ReviewTicket,
    SessionState,
    TaggedValue,
    ToolClass,
    VersionSet,
    Zone,
)


@pytest.mark.unit
def test_contracts_version_constant() -> None:
    assert CONTRACTS_VERSION == "0.1.0"


@pytest.mark.unit
def test_enum_members_and_values() -> None:
    assert Decision.ALLOW == "ALLOW"
    assert Decision.DENY == "DENY"
    assert Decision.REVIEW == "REVIEW"

    assert PolicyVerdict.PROHIBIT == "PROHIBIT"
    assert PolicyVerdict.PERMIT == "PERMIT"
    assert PolicyVerdict.UNDETERMINED == "UNDETERMINED"
    assert PolicyVerdict.EVIDENCE_MISSING == "EVIDENCE_MISSING"

    assert MonitorVerdict.BENIGN == "BENIGN"
    assert MonitorVerdict.SUSPICIOUS == "SUSPICIOUS"
    assert MonitorVerdict.UNKNOWN == "UNKNOWN"
    assert MonitorVerdict.NOT_CONSULTED == "NOT_CONSULTED"

    assert ToolClass.READ_LOW == "READ_LOW"
    assert ToolClass.PRIVILEGED_ADMIN == "PRIVILEGED_ADMIN"

    assert Classification.CONFIDENTIAL == "CONFIDENTIAL"
    assert Zone.EXTERNAL == "EXTERNAL"
    assert Provenance.TOOL_TYPED == "TOOL_TYPED"
    assert ExecStatus.EXEC_UNKNOWN == "EXEC_UNKNOWN"
    assert OutcomeContract.SYNCHRONOUS_CONFIRMED == "SYNCHRONOUS_CONFIRMED"
    assert ConfirmationLevel.CONFIRMED_COMPLETED == "CONFIRMED_COMPLETED"
    assert ReviewStatus.PENDING == "PENDING"
    assert EventType.EXEC_UNKNOWN == "EXEC_UNKNOWN"


@pytest.mark.unit
def test_action_request_valid() -> None:
    req = ActionRequest(
        session_id="sess_123",
        tool="execute_export",
        arguments={"destination": "internal_archive"},
        declared_intent="Backup logs",
    )
    assert req.schema_version == "0.1.0"
    assert req.session_id == "sess_123"
    assert req.tool == "execute_export"
    assert req.arguments == {"destination": "internal_archive"}
    assert req.declared_intent == "Backup logs"


@pytest.mark.unit
def test_action_request_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate({
            "schema_version": "0.1.0",
            "session_id": "sess_123",
            "tool": "select_resource",
            "arguments": {},
            "unauthorized_field": "smuggled_payload",
        })


@pytest.mark.unit
def test_canonical_action_validation() -> None:
    action = CanonicalAction(
        action_id="act_001",
        session_id="sess_123",
        seq=1,
        tool="select_resource",
        arguments={"resource_ref": "customer_records"},
        action_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert action.seq == 1
    assert action.action_id == "act_001"

    with pytest.raises(ValidationError):
        CanonicalAction.model_validate({
            "action_id": "act_001",
            "session_id": "sess_123",
            "seq": "invalid_integer",
            "tool": "select_resource",
            "arguments": {},
            "action_hash": "abc",
        })


@pytest.mark.unit
def test_session_state_and_tagged_values() -> None:
    tagged = TaggedValue(value="CONFIDENTIAL", provenance=Provenance.REGISTRY)
    assert tagged.provenance == Provenance.REGISTRY

    res_ref = ResourceRef(
        ref="customer_records",
        classification=Classification.CONFIDENTIAL,
        selected_seq=1,
    )
    dest_ref = DestinationRef(ref="external_storage", zone=Zone.EXTERNAL)

    state = SessionState(
        head_hash="31ab...78",
        seq=2,
        bound_resource=res_ref,
        selected_resources=[res_ref],
        destination=dest_ref,
        job_created=True,
        egress_counters={"EXTERNAL": EgressCounter(rows=100, bytes=4096)},
    )
    assert state.state_version == "0.1.0"
    assert state.bound_resource is not None
    assert state.bound_resource.classification == Classification.CONFIDENTIAL
    assert state.egress_counters["EXTERNAL"].rows == 100


@pytest.mark.unit
def test_decision_record_and_versions() -> None:
    versions = VersionSet(
        contracts="0.1.0",
        policy_hash="pol_hash_123",
        registry_hash="reg_hash_456",
        firewall_config_hash="cfg_hash_789",
    )
    record = DecisionRecord(
        decision_id="dec_001",
        action_id="act_001",
        action_hash="hash_001",
        state_head_hash="head_001",
        decision=Decision.DENY,
        reason_codes=["POLICY_PROHIBIT:R1"],
        policy_verdict=PolicyVerdict.PROHIBIT,
        versions=versions,
        timings_ms={"total": 1.2},
    )
    assert record.decision == Decision.DENY
    assert record.monitor_verdict == MonitorVerdict.NOT_CONSULTED
    assert record.versions.contracts == "0.1.0"


@pytest.mark.unit
def test_result_envelope_valid() -> None:
    envelope = ResultEnvelope(
        has_value=True,
        value={"rows_exported": 500},
        outcome_contract=OutcomeContract.SYNCHRONOUS_CONFIRMED,
        confirmation_level=ConfirmationLevel.CONFIRMED_COMPLETED,
    )
    assert envelope.has_value is True
    assert envelope.error is None
    assert envelope.outcome_contract == OutcomeContract.SYNCHRONOUS_CONFIRMED

    err_envelope = ResultEnvelope(
        has_value=False,
        error={"code": "EXEC_UNKNOWN_AMBIGUOUS", "message": "Crash during tool call"},
        outcome_contract=OutcomeContract.SYNCHRONOUS_CONFIRMED,
        confirmation_level=ConfirmationLevel.NONE,
    )
    assert err_envelope.has_value is False
    assert err_envelope.value is None


@pytest.mark.unit
def test_evidence_receipt_and_review_ticket() -> None:
    receipt = EvidenceReceipt(
        session_id="sess_01",
        action_id="act_01",
        token_id="tok_01",
        source_tool_name="system_state_inspector",
        observed_state={"filesystem_state": "CLEAN"},
        observed_timestamp_ms=1729770000000,
        signature="hmac_sig_123",
    )
    assert receipt.source_tool_name == "system_state_inspector"

    ticket = ReviewTicket(
        ticket_id="tick_001",
        action_id="act_001",
        action_hash="hash_001",
        created_ms=1000,
        expires_ms=5000,
        summary=ReviewerView(
            tool="execute_export",
            typed_arguments={},
            policy_verdict=PolicyVerdict.UNDETERMINED,
        ),
    )
    assert ticket.status == ReviewStatus.PENDING

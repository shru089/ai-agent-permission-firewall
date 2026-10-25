"""
Golden JSON-Schema snapshot test for contracts v0.1.0.
Source: 08_IMPLEMENTATION_ROADMAP.md Phase 1, 05_TECHNICAL_SPEC.md §12
"""

import json
from pathlib import Path

import pytest

from firewall.contracts import (
    ActionRequest,
    AuthorizationToken,
    CanonicalAction,
    DecisionRecord,
    DestinationRef,
    EgressCounter,
    Event,
    EvidenceReceipt,
    ExportJob,
    MonitorAssessment,
    MonitorView,
    PolicyResult,
    ResourceRef,
    ResultEnvelope,
    ReviewerView,
    ReviewTicket,
    SessionState,
    StateEventEnvelope,
    TaggedValue,
    VersionSet,
)

SNAPSHOT_PATH = Path(__file__).resolve().parent.parent / "golden" / "contracts_schema_snapshot.json"


@pytest.mark.unit
def test_contracts_golden_schema_snapshot() -> None:
    """
    Asserts that the exported JSON Schemas of all shared contract models
    match the committed golden snapshot byte-for-byte.
    Any alteration to contracts/ requires approval from all four owners.
    """
    assert SNAPSHOT_PATH.exists(), f"Golden snapshot file missing at {SNAPSHOT_PATH}"

    with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
        golden_schemas = json.load(f)

    current_schemas = {
        "ActionRequest": ActionRequest.model_json_schema(),
        "CanonicalAction": CanonicalAction.model_json_schema(),
        "Event": Event.model_json_schema(),
        "SessionState": SessionState.model_json_schema(),
        "PolicyResult": PolicyResult.model_json_schema(),
        "MonitorView": MonitorView.model_json_schema(),
        "MonitorAssessment": MonitorAssessment.model_json_schema(),
        "DecisionRecord": DecisionRecord.model_json_schema(),
        "AuthorizationToken": AuthorizationToken.model_json_schema(),
        "ReviewTicket": ReviewTicket.model_json_schema(),
        "ReviewerView": ReviewerView.model_json_schema(),
        "ResultEnvelope": ResultEnvelope.model_json_schema(),
        "StateEventEnvelope": StateEventEnvelope.model_json_schema(),
        "EvidenceReceipt": EvidenceReceipt.model_json_schema(),
        "TaggedValue": TaggedValue.model_json_schema(),
        "ResourceRef": ResourceRef.model_json_schema(),
        "DestinationRef": DestinationRef.model_json_schema(),
        "ExportJob": ExportJob.model_json_schema(),
        "EgressCounter": EgressCounter.model_json_schema(),
        "VersionSet": VersionSet.model_json_schema(),
    }

    assert set(current_schemas.keys()) == set(golden_schemas.keys()), (
        f"Model set changed! Current: {set(current_schemas.keys())}, "
        f"Golden: {set(golden_schemas.keys())}"
    )

    mismatches = []
    for model_name, current_schema in current_schemas.items():
        golden_schema = golden_schemas[model_name]
        if current_schema != golden_schema:
            mismatches.append(model_name)

    assert not mismatches, (
        f"Contract schemas drifted from golden snapshot for: {mismatches}. "
        "Any change to contracts/ requires unanimous review from all four owners."
    )

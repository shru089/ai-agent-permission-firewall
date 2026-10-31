from __future__ import annotations

import json
from pathlib import Path

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


def main() -> None:
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

    snapshot_path = Path(__file__).resolve().parents[1] / "tests" / "golden" / "contracts_schema_snapshot.json"
    snapshot_path.write_text(
        json.dumps(current_schemas, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(current_schemas)} schema entries to {snapshot_path}")


if __name__ == "__main__":
    main()

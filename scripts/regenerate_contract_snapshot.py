"""
Regenerate tests/golden/contracts_schema_snapshot.json from current contract models.

This script exports JSON Schema definitions for all shared contract models
and writes them to the golden snapshot file with exact ordering and formatting.
"""

import json
from pathlib import Path
import sys

# Ensure repository root and src are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

SNAPSHOT_PATH = REPO_ROOT / "tests" / "golden" / "contracts_schema_snapshot.json"


def generate_schemas() -> dict[str, dict]:
    return {
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


def main() -> None:
    schemas = generate_schemas()
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SNAPSHOT_PATH, "w", encoding="utf-8") as f:
        json.dump(schemas, f, indent=2)
        f.write("\n")
    print(f"Successfully regenerated snapshot at {SNAPSHOT_PATH} with {len(schemas)} models.")


if __name__ == "__main__":
    main()
"""
Deterministic State Engine (C2) for AI Agent Permission Firewall.
Computes observable session state S_t as a pure fold over typed events:
    S_t = Φ(H_t, Registry)
Source: 05_TECHNICAL_SPEC.md §8.1, 03_MATHEMATICAL_MODEL_AND_METRICS.md §1,
        01_THREAT_MODEL.md (INV-02, INV-06, INV-07, INV-12)
"""

import hashlib
from enum import Enum
from typing import Any, Optional, Sequence

from firewall.contracts.enums import (
    Anomaly,
    Classification,
    EventType,
    Provenance,
    Zone,
)
from firewall.contracts.hashing import canonical_json, compute_genesis_head
from firewall.contracts.models import (
    CONTRACTS_VERSION,
    DestinationRef,
    EgressCounter,
    Event,
    EvidenceReceipt,
    ExportJob,
    ResourceRef,
    SessionState,
    StateEventEnvelope,
    TaggedValue,
)
from firewall.state.errors import StateContinuityError, StateIntegrityError
from firewall.state.registry import Registry


class BindingMode(str, Enum):
    """
    Binding mode controlling how selected resources and export jobs associate.
    - implicit: [P1] benchmark convention; last selected resource binds to export.
    - explicit: realistic tool API convention; export job explicitly binds refs.
    Source: 05_TECHNICAL_SPEC.md §7.2, §8.1; OQ-06
    """

    IMPLICIT = "implicit"
    EXPLICIT = "explicit"


def initial_state(session_id: str) -> SessionState:
    """
    Constructs the initial deterministic state S_0 for a session (INV-12).
    head_hash is initialized from compute_genesis_head(session_id).
    """
    return SessionState(
        state_version=CONTRACTS_VERSION,
        head_hash=compute_genesis_head(session_id),
        seq=0,
        bound_resource=None,
        selected_resources=[],
        jobs={},
        destination=None,
        job_created=False,
        egress_counters={},
        anomalies=[],
        indeterminate_state=0,
    )


def compute_state_head(prior_head: str, event_data: Any) -> str:
    """
    Cryptographically binds prior head hash and event data via RFC 8785 canonical JSON:
        hash = SHA-256(prior_head || canonical_json(event_data))
    Guarantees strict determinism, tamper-evidence, and key-order invariance (INV-09, INV-12).
    """
    canonical_bytes = canonical_json(event_data, reject_floats=False)
    hasher = hashlib.sha256()
    hasher.update(prior_head.encode("utf-8"))
    hasher.update(canonical_bytes)
    return hasher.hexdigest()


def _extract_event_canonical_data(event: StateEventEnvelope | Event) -> dict[str, Any]:
    """Serializes event fields into a canonical preimage structure for head hashing."""
    if isinstance(event, StateEventEnvelope):
        return {
            "session_id": event.session_id,
            "seq": event.seq,
            "prior_head": event.prior_head,
            "event_type": event.event_type,
            "action_id": event.action_id,
            "token_id": event.token_id,
            "payload": event.payload,
        }
    elif isinstance(event, Event):
        fields_dump: dict[str, Any] = {}
        for k, v in event.fields.items():
            if isinstance(v, TaggedValue):
                fields_dump[k] = v.model_dump()
            else:
                fields_dump[k] = v
        return {
            "session_id": event.session_id,
            "seq": event.seq,
            "type": event.type,
            "action_id": event.action_id,
            "fields": fields_dump,
            "free_text": event.free_text,
            "decision": event.decision.value if event.decision else None,
        }
    raise StateIntegrityError(f"Unsupported event type for hashing: {type(event)}")


def _extract_tool_and_arguments(
    event: StateEventEnvelope | Event,
) -> tuple[str, dict[str, Any], dict[str, Any], Any]:
    """
    Extracts tool name, arguments, tagged fields, and evidence payload
    from either a StateEventEnvelope or an Event model.
    """
    tool: str = ""
    arguments: dict[str, Any] = {}
    fields: dict[str, Any] = {}
    evidence: Any = None

    if isinstance(event, StateEventEnvelope):
        payload = event.payload or {}
        tool = str(payload.get("tool") or payload.get("action_tool") or "")
        raw_args = payload.get("arguments")
        if isinstance(raw_args, dict):
            arguments = dict(raw_args)
        raw_fields = payload.get("fields")
        if isinstance(raw_fields, dict):
            fields = dict(raw_fields)
        evidence = payload.get("evidence")

        if not tool and "tool" in fields:
            val = fields["tool"]
            tool = val.value if isinstance(val, TaggedValue) else str(val)

    elif isinstance(event, Event):
        fields = dict(event.fields)
        if "tool" in fields:
            t_val = fields["tool"]
            tool = t_val.value if isinstance(t_val, TaggedValue) else str(t_val)
        if "arguments" in fields:
            a_val = fields["arguments"]
            val = a_val.value if isinstance(a_val, TaggedValue) else a_val
            if isinstance(val, dict):
                arguments = dict(val)
        evidence = fields.get("evidence")

    return tool, arguments, fields, evidence


def _extract_trusted_row_count(
    fields: dict[str, Any],
    evidence: Any,
    payload: Optional[dict[str, Any]] = None,
) -> tuple[Optional[int], int]:
    """
    Extracts row and byte counts strictly from validated execution evidence (INV-07).
    Accepts only Provenance.TOOL_TYPED, Provenance.GATEWAY, or EvidenceReceipt.
    Any values tagged with TOOL_FREETEXT or AGENT_CLAIM are strictly rejected.
    """
    rows: Optional[int] = None
    bytes_count: int = 0

    # 1. Check EvidenceReceipt if provided
    if isinstance(evidence, EvidenceReceipt):
        obs = evidence.observed_state or {}
        if "rows" in obs or "rows_exported" in obs:
            val = obs.get("rows", obs.get("rows_exported"))
            if val is not None:
                rows = int(val)
        if "bytes" in obs or "bytes_exported" in obs:
            b_val = obs.get("bytes", obs.get("bytes_exported"))
            if b_val is not None:
                bytes_count = int(b_val)
        return rows, bytes_count

    # 2. Check tagged fields for rows_exported or rows
    for key in ("rows_exported", "rows"):
        tv = fields.get(key)
        if tv is not None:
            if isinstance(tv, TaggedValue):
                if tv.provenance in (
                    Provenance.TOOL_TYPED,
                    Provenance.GATEWAY,
                    Provenance.REGISTRY,
                ):
                    rows = int(tv.value)
                    break
            elif isinstance(tv, dict) and "provenance" in tv:
                p_str = tv.get("provenance")
                if p_str in (
                    Provenance.TOOL_TYPED.value,
                    Provenance.GATEWAY.value,
                    Provenance.REGISTRY.value,
                    Provenance.TOOL_TYPED,
                    Provenance.GATEWAY,
                    Provenance.REGISTRY,
                ):
                    rows = int(tv.get("value", 0))
                    break

    for key in ("bytes_exported", "bytes"):
        tv = fields.get(key)
        if tv is not None:
            if isinstance(tv, TaggedValue):
                if tv.provenance in (
                    Provenance.TOOL_TYPED,
                    Provenance.GATEWAY,
                    Provenance.REGISTRY,
                ):
                    bytes_count = int(tv.value)
                    break
            elif isinstance(tv, dict) and "provenance" in tv:
                p_str = tv.get("provenance")
                if p_str in (
                    Provenance.TOOL_TYPED.value,
                    Provenance.GATEWAY.value,
                    Provenance.REGISTRY.value,
                    Provenance.TOOL_TYPED,
                    Provenance.GATEWAY,
                    Provenance.REGISTRY,
                ):
                    bytes_count = int(tv.get("value", 0))
                    break

    # 3. Check payload level if provided
    if rows is None and payload:
        if "rows" in payload and "provenance" in payload:
            prov = payload["provenance"]
            if prov in (
                Provenance.TOOL_TYPED,
                Provenance.GATEWAY,
                Provenance.REGISTRY,
                Provenance.TOOL_TYPED.value,
                Provenance.GATEWAY.value,
                Provenance.REGISTRY.value,
            ):
                rows = int(payload["rows"])
                if "bytes" in payload:
                    bytes_count = int(payload.get("bytes", 0))

    return rows, bytes_count


def apply_event(
    state: SessionState,
    event: StateEventEnvelope | Event,
    registry: Registry,
    expected_session_id: Optional[str] = None,
    binding_mode: BindingMode = BindingMode.IMPLICIT,
) -> SessionState:
    """
    Pure state transition function: Φ(S_{t-1}, e_t, Registry) -> S_t (INV-12).

    Validates:
    - Authoritative expected_session_id is mandatory and non-empty (SEC-03).
    - Event session_id strictly matches expected_session_id on every transition.
    - Genesis head hash matches expected_session_id on first transition (seq == 0).
    - Monotonic sequence continuity (e_t.seq == S_{t-1}.seq + 1).
    - Prior-head hash continuity (e_t.prior_head == S_{t-1}.head_hash).
    - Provenance integrity: only registry/gateway/typed evidence sets security state (INV-07).
    - Denied/failed actions append to hash chain without mutating security state.
    """
    # 1. Authoritative Session Identity Validation (SEC-03)
    if (
        expected_session_id is None
        or not isinstance(expected_session_id, str)
        or not expected_session_id.strip()
    ):
        raise StateContinuityError(
            "Missing or empty expected_session_id: authoritative session identity "
            "is mandatory for every state transition"
        )

    if event.session_id != expected_session_id:
        raise StateContinuityError(
            f"Session identity mismatch: expected '{expected_session_id}', got '{event.session_id}'"
        )

    if state.seq == 0:
        expected_genesis = compute_genesis_head(expected_session_id)
        if state.head_hash != expected_genesis:
            raise StateContinuityError(
                f"Session genesis mismatch: state genesis head {state.head_hash} "
                f"does not match expected session '{expected_session_id}' "
                f"(computed: {expected_genesis})"
            )

    # 2. Monotonic Sequence Continuity Validation
    if event.seq != state.seq + 1:
        raise StateContinuityError(
            f"Invalid event sequence: expected {state.seq + 1}, got {event.seq}"
        )

    # 3. Prior-Head Hash Continuity Validation
    if isinstance(event, StateEventEnvelope):
        if event.prior_head != state.head_hash:
            raise StateContinuityError(
                f"Prior-head mismatch: state head is {state.head_hash}, "
                f"event asserts prior_head {event.prior_head}"
            )

    # 4. Compute next head hash
    canonical_preimage = _extract_event_canonical_data(event)
    next_head = compute_state_head(state.head_hash, canonical_preimage)

    # 5. Extract event type and determine execution status
    event_type_str = event.event_type if isinstance(event, StateEventEnvelope) else event.type
    is_executed = event_type_str == EventType.EXECUTED.value

    # If action was not executed (e.g. ACTION_DENIED, FAILED, EXEC_UNKNOWN, REVIEW_RESOLVED),
    # update audit sequence and head_hash, but leave all security-relevant fields unchanged.
    if not is_executed:
        return state.model_copy(
            update={
                "seq": event.seq,
                "head_hash": next_head,
            }
        )

    # 6. Apply Tool Effect on State (Executed Action)
    tool, arguments, fields, evidence = _extract_tool_and_arguments(event)
    payload_dict = event.payload if isinstance(event, StateEventEnvelope) else None

    # Clone state fields for pure update
    bound_resource = state.bound_resource
    selected_resources = list(state.selected_resources)
    jobs = dict(state.jobs)
    destination = state.destination
    job_created = state.job_created
    egress_counters = {k: v.model_copy() for k, v in state.egress_counters.items()}
    anomalies = list(state.anomalies)
    indeterminate_state = state.indeterminate_state

    # Tool: select_resource(resource_ref)
    if tool == "select_resource":
        ref = arguments.get("resource_ref") or arguments.get("ref")
        if not ref and "resource_ref" in fields:
            val_tv = fields["resource_ref"]
            if isinstance(val_tv, TaggedValue):
                if val_tv.provenance not in (Provenance.TOOL_FREETEXT, Provenance.AGENT_CLAIM):
                    ref = str(val_tv.value)
            else:
                ref = str(val_tv)

        if not ref:
            if Anomaly.UNKNOWN_CLASSIFICATION.value not in anomalies:
                anomalies.append(Anomaly.UNKNOWN_CLASSIFICATION.value)
            indeterminate_state += 1
        else:
            # Look up classification strictly from the trusted registry (INV-07, A-05)
            # Forged classification claims in free_text or agent claims are strictly ignored.
            classification = registry.get_resource_classification(ref)
            if not registry.has_resource(ref):
                classification = Classification.UNKNOWN
                if Anomaly.UNKNOWN_CLASSIFICATION.value not in anomalies:
                    anomalies.append(Anomaly.UNKNOWN_CLASSIFICATION.value)
                indeterminate_state += 1

            new_res_ref = ResourceRef(
                ref=ref,
                classification=classification,
                selected_seq=event.seq,
            )
            selected_resources.append(new_res_ref)

            if binding_mode == BindingMode.IMPLICIT:
                if bound_resource is not None and bound_resource.ref != ref:
                    if Anomaly.CONFLICTING_SELECTION.value not in anomalies:
                        anomalies.append(Anomaly.CONFLICTING_SELECTION.value)
                bound_resource = new_res_ref

    # Tool: reset_context()
    elif tool == "reset_context":
        bound_resource = None
        destination = None
        job_created = False

    # Tool: configure_destination(destination_ref)
    elif tool == "configure_destination":
        dest_ref = arguments.get("destination_ref") or arguments.get("ref")
        if not dest_ref and "destination_ref" in fields:
            val_tv = fields["destination_ref"]
            if isinstance(val_tv, TaggedValue):
                if val_tv.provenance not in (Provenance.TOOL_FREETEXT, Provenance.AGENT_CLAIM):
                    dest_ref = str(val_tv.value)
            else:
                dest_ref = str(val_tv)

        if not dest_ref:
            destination = DestinationRef(ref="unknown", zone=Zone.UNKNOWN)
            if Anomaly.UNKNOWN_DESTINATION.value not in anomalies:
                anomalies.append(Anomaly.UNKNOWN_DESTINATION.value)
            indeterminate_state += 1
        else:
            zone = registry.get_destination_zone(dest_ref)
            if not registry.has_destination(dest_ref):
                zone = Zone.UNKNOWN
                if Anomaly.UNKNOWN_DESTINATION.value not in anomalies:
                    anomalies.append(Anomaly.UNKNOWN_DESTINATION.value)
                indeterminate_state += 1
            destination = DestinationRef(ref=dest_ref, zone=zone)

    # Tool: create_export_job()
    elif tool == "create_export_job":
        if binding_mode == BindingMode.IMPLICIT:
            job_created = True
        elif binding_mode == BindingMode.EXPLICIT:
            job_created = True
            job_id = str(arguments.get("job_id", f"job_{event.seq}"))
            raw_res = arguments.get("resource_refs") or arguments.get("resource_ref") or []
            if isinstance(raw_res, str):
                r_refs = [raw_res]
            elif isinstance(raw_res, (list, tuple)):
                r_refs = [str(r) for r in raw_res]
            else:
                r_refs = []

            dest_ref_job = str(arguments.get("destination_ref", ""))
            job_zone = (
                registry.get_destination_zone(dest_ref_job)
                if dest_ref_job
                else Zone.UNKNOWN
            )
            if dest_ref_job and not registry.has_destination(dest_ref_job):
                if Anomaly.UNKNOWN_DESTINATION.value not in anomalies:
                    anomalies.append(Anomaly.UNKNOWN_DESTINATION.value)
                indeterminate_state += 1

            for r in r_refs:
                if not registry.has_resource(r):
                    if Anomaly.UNKNOWN_CLASSIFICATION.value not in anomalies:
                        anomalies.append(Anomaly.UNKNOWN_CLASSIFICATION.value)
                    indeterminate_state += 1

            jobs[job_id] = ExportJob(
                job_id=job_id,
                resource_refs=r_refs,
                destination_ref=dest_ref_job,
                zone=job_zone,
                created_seq=event.seq,
            )

    # Tool: execute_export()
    elif tool == "execute_export":
        # Resolve target destination zone
        target_zone = Zone.UNKNOWN
        if binding_mode == BindingMode.EXPLICIT:
            explicit_job_id = str(arguments["job_id"]) if arguments.get("job_id") else None
            if explicit_job_id and explicit_job_id in jobs:
                target_zone = jobs[explicit_job_id].zone
            elif destination is not None:
                target_zone = destination.zone
        else:
            if destination is not None:
                target_zone = destination.zone

        # Extract verified execution evidence (INV-07)
        rows_added, bytes_added = _extract_trusted_row_count(fields, evidence, payload_dict)

        if rows_added is None:
            # Missing or unverified security-critical execution evidence
            # Must never silently assume safe/zero (SO-5, INV-04)
            indeterminate_state += 1
            if "MISSING_EXECUTION_EVIDENCE" not in anomalies:
                anomalies.append("MISSING_EXECUTION_EVIDENCE")
        else:
            zone_key = target_zone.value
            current_counter = egress_counters.get(
                zone_key, EgressCounter(rows=0, bytes=0, rows_plus_pending=0)
            )
            updated_rows = current_counter.rows + rows_added
            updated_bytes = current_counter.bytes + bytes_added
            egress_counters[zone_key] = EgressCounter(
                rows=updated_rows,
                bytes=updated_bytes,
                rows_plus_pending=updated_rows,
            )

    # Other tools (e.g. validate_schema, check_disk_space, ping_database, read_resource)
    # produce only TOOL_FREETEXT or read-only effects; they do not alter security state.

    return SessionState(
        state_version=CONTRACTS_VERSION,
        head_hash=next_head,
        seq=event.seq,
        bound_resource=bound_resource,
        selected_resources=selected_resources,
        jobs=jobs,
        destination=destination,
        job_created=job_created,
        egress_counters=egress_counters,
        anomalies=anomalies,
        indeterminate_state=indeterminate_state,
    )


def replay_events(
    events: Sequence[StateEventEnvelope | Event],
    session_id: str,
    registry: Registry,
    binding_mode: BindingMode = BindingMode.IMPLICIT,
) -> SessionState:
    """
    Reconstructs observable session state S_t by replaying an ordered event log from S_0 (INV-12).
    Pure, deterministic, bit-for-bit reproducible.
    """
    if not session_id or not isinstance(session_id, str) or not session_id.strip():
        raise StateContinuityError(
            "Missing or empty session_id: replay requires authoritative session identity"
        )
    state = initial_state(session_id)
    for evt in events:
        state = apply_event(
            state=state,
            event=evt,
            registry=registry,
            expected_session_id=session_id,
            binding_mode=binding_mode,
        )
    return state

"""
Allow-listed information projections (views) per consumer.
Enforces information barriers: monitors and reviewers see only their allow-listed projection.
Source: 05_TECHNICAL_SPEC.md §8.2, 01_THREAT_MODEL.md (INV-08)
"""

import json
from typing import Any, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from firewall.contracts.enums import PolicyVerdict
from firewall.contracts.models import (
    CanonicalAction,
    Event,
    MonitorAssessment,
    MonitorView,
    ReviewerView,
    SessionState,
    StateEventEnvelope,
)
from firewall.state.registry import Registry


class PolicyView(BaseModel):
    """
    Allow-listed projection for the deterministic policy engine.
    Contains canonical action, observable session state, and registry facts.
    """

    action: CanonicalAction
    state: SessionState
    registry_snapshot: dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")


def build_policy_view(
    action: CanonicalAction,
    state: SessionState,
    registry: Registry,
) -> PolicyView:
    """Build the allow-listed PolicyView projection."""
    return PolicyView(
        action=action,
        state=state,
        registry_snapshot=registry.snapshot(),
    )


def format_transcript(
    events: Sequence[Event | StateEventEnvelope],
    max_output_chars: int = 500,
) -> str:
    """
    Deterministically formats event history into a plain text transcript (INV-08, SEC-05).
    Includes sequence number, event type, action ID, canonical tool name, typed arguments,
    and bounded output text per [P1] specification.
    Excludes any oracle labels, future actions, or scenario metadata.
    """
    lines: list[str] = []
    for evt in events:
        if isinstance(evt, StateEventEnvelope):
            parts = [f"[{evt.seq}] {evt.event_type} action_id={evt.action_id}"]
            payload = evt.payload or {}
            tool = payload.get("tool") or payload.get("action_tool")
            if tool:
                parts.append(f"tool={tool}")
            arguments = payload.get("arguments")
            if arguments is not None:
                if isinstance(arguments, dict):
                    parts.append(f"arguments={json.dumps(arguments, sort_keys=True)}")
                else:
                    parts.append(f"arguments={arguments}")
            if evt.token_id:
                parts.append(f"token_id={evt.token_id}")
            output = (
                payload.get("output")
                or payload.get("free_text")
                or payload.get("error")
            )
            if output is not None:
                bounded_output = str(output)[:max_output_chars]
                parts.append(f"output={bounded_output}")
            lines.append(" ".join(parts))
        elif isinstance(evt, Event):
            parts = [f"[{evt.seq}] {evt.type} action_id={evt.action_id}"]
            tool_field = evt.fields.get("tool")
            if tool_field is not None:
                parts.append(f"tool={tool_field.value}")
            args_field = evt.fields.get("arguments")
            if args_field is not None:
                if isinstance(args_field.value, dict):
                    parts.append(f"arguments={json.dumps(args_field.value, sort_keys=True)}")
                else:
                    parts.append(f"arguments={args_field.value}")
            if evt.decision:
                parts.append(f"decision={evt.decision.value}")
            if evt.free_text:
                bounded_output = str(evt.free_text)[:max_output_chars]
                parts.append(f"output={bounded_output}")
            lines.append(" ".join(parts))
    return "\n".join(lines)


def build_state_summary(
    state: SessionState,
    events: Sequence[Event | StateEventEnvelope],
) -> dict[str, Any]:
    """
    Builds allow-listed typed state summary for HybridMonitor projection.
    Contains only typed fields and event references; no labels or oracle data.
    """
    event_refs = [evt.action_id for evt in events if hasattr(evt, "action_id") and evt.action_id]
    return {
        "bound_resource": state.bound_resource.model_dump() if state.bound_resource else None,
        "selected_resources": [r.model_dump() for r in state.selected_resources],
        "destination": state.destination.model_dump() if state.destination else None,
        "job_created": state.job_created,
        "jobs": {k: v.model_dump() for k, v in state.jobs.items()},
        "egress_counters": {k: v.model_dump() for k, v in state.egress_counters.items()},
        "anomalies": list(state.anomalies),
        "indeterminate_state": state.indeterminate_state,
        "event_refs": event_refs,
    }


def build_monitor_view(
    monitor_type: str,
    action: CanonicalAction,
    state: SessionState,
    registry: Registry,
    history: Sequence[Event | StateEventEnvelope] = (),
    goal: Optional[dict[str, Any]] = None,
    policy_text: Optional[str] = None,
) -> MonitorView:
    """
    Build allow-listed projection for a specific monitor type.
    Enforces strict information barrier (INV-08):
    - ActionOnly sees action + registry facts of named entities + goal + policy text.
    - Transcript adds text transcript of H_t.
    - Hybrid adds state_summary (typed fields + event refs).
    - Labels and scenario secrets never enter any view.
    """
    registry_facts = registry.get_facts_for_action(action.tool, action.arguments)

    transcript: Optional[str] = None
    state_summary: Optional[dict[str, Any]] = None

    if monitor_type in ("Transcript", "B5"):
        transcript = format_transcript(history)
    elif monitor_type in ("Hybrid", "P1"):
        state_summary = build_state_summary(state, history)

    return MonitorView(
        monitor_id=monitor_type,
        action=action,
        registry_facts=registry_facts,
        goal=goal,
        policy_text=policy_text,
        transcript=transcript,
        state_summary=state_summary,
    )


def build_reviewer_view(
    action: CanonicalAction,
    policy_verdict: PolicyVerdict,
    reason_codes: list[str],
    state: SessionState,
    monitor_assessment: Optional[MonitorAssessment] = None,
) -> ReviewerView:
    """
    Build allow-listed ReviewerView for human review tickets.
    SECURITY: 'declared_intent' from agent is strictly forbidden from state_facts (INV-07, 05 §8.2).
    State facts are derived exclusively from typed, gateway-attested state.
    """
    state_facts = {
        "bound_resource": state.bound_resource.model_dump() if state.bound_resource else None,
        "selected_resources": [r.model_dump() for r in state.selected_resources],
        "destination": state.destination.model_dump() if state.destination else None,
        "job_created": state.job_created,
        "jobs": {k: v.model_dump() for k, v in state.jobs.items()},
        "egress_counters": {k: v.model_dump() for k, v in state.egress_counters.items()},
        "anomalies": list(state.anomalies),
    }

    return ReviewerView(
        tool=action.tool,
        typed_arguments=action.arguments,
        policy_verdict=policy_verdict,
        reason_codes=list(reason_codes),
        state_facts=state_facts,
        monitor_assessment=monitor_assessment,
    )

"""
Allow-listed information projections (views) per consumer.
Enforces information barriers: monitors and reviewers see only their allow-listed projection.
Source: 05_TECHNICAL_SPEC.md §8.2, 01_THREAT_MODEL.md (INV-08)
"""

import copy
import json
import re
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

SENSITIVE_KEY_NAMES = {
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "password",
    "passwd",
    "token",
    "tokens",
    "token_id",
    "auth_token",
    "access_token",
    "session_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "bearer",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
}

SENSITIVE_KEY_SUBSTRINGS = (
    "api_key",
    "apikey",
    "secret",
    "password",
    "credential",
    "private_key",
    "auth_token",
    "access_token",
    "bearer_token",
    "session_token",
    "client_secret",
)

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)
_SECRET_KV_PATTERN = re.compile(
    r"""(?i)\b(api[_-]?key|secret(?:[_-]?key)?|password|passwd|token[s]?|token[_-]?id|auth[_-]?token|access[_-]?token|session[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|bearer|credential[s]?)\b\s*[:=]\s*(['"]?)([^'"\s,;{}]{3,})\2"""
)
_BEARER_PATTERN = re.compile(r"""(?i)\b(bearer\s+)([A-Za-z0-9\-_.~+/=]{6,})""")
_JWT_PATTERN = re.compile(r"""\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\b""")
_TOKEN_PREFIX_PATTERN = re.compile(
    r"""\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9\-]{16,})\b"""
)


def is_sensitive_field(key: str) -> bool:
    """Check if a field name matches known sensitive credentials, tokens, or keys."""
    k = key.lower().strip()
    if k in SENSITIVE_KEY_NAMES:
        return True
    return any(sub in k for sub in SENSITIVE_KEY_SUBSTRINGS)


def scrub_text(text: str) -> str:
    """
    Scrub sensitive credentials (bearer tokens, passwords, API keys, private keys,
    high-entropy tokens) from plain text, logs, error strings, and transcripts.
    """
    if not text or not isinstance(text, str):
        return text

    # Redact PEM private key blocks first
    res = _PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)

    # Redact standard JWTs
    res = _JWT_PATTERN.sub("[REDACTED_JWT]", res)

    # Redact known API token prefixes
    res = _TOKEN_PREFIX_PATTERN.sub("[REDACTED_TOKEN]", res)

    # Redact Bearer tokens
    res = _BEARER_PATTERN.sub(r"\1[REDACTED]", res)

    # Redact key-value assignments
    res = _SECRET_KV_PATTERN.sub(r"\1=\2[REDACTED]\2", res)

    return res


def sanitize_data(obj: Any) -> Any:
    """
    Recursively remove sensitive data (credentials, tokens, API keys, raw secrets)
    from dictionaries, lists, tuples, and string values before exposing to monitors.
    """
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and is_sensitive_field(k):
                continue
            cleaned[k] = sanitize_data(v)
        return cleaned
    elif isinstance(obj, list):
        return [sanitize_data(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_data(item) for item in obj)
    elif isinstance(obj, set):
        return {sanitize_data(item) for item in obj}
    elif isinstance(obj, str):
        trimmed = obj.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (
            trimmed.startswith("[") and trimmed.endswith("]")
        ):
            try:
                parsed = json.loads(trimmed)
                cleaned_parsed = sanitize_data(parsed)
                return scrub_text(json.dumps(cleaned_parsed, sort_keys=True))
            except Exception:
                pass
        return scrub_text(obj)
    return obj


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
    Excludes internal tokens and sensitive credentials across arguments, outputs, free_text,
    and errors.
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
                sanitized_args = sanitize_data(copy.deepcopy(arguments))
                if isinstance(sanitized_args, dict):
                    parts.append(f"arguments={json.dumps(sanitized_args, sort_keys=True)}")
                else:
                    parts.append(f"arguments={sanitized_args}")

            # Scrub output, free_text, and error fields
            out_val = payload.get("output")
            ft_val = payload.get("free_text")
            err_val = payload.get("error")

            if out_val is not None:
                sanitized_out = sanitize_data(copy.deepcopy(out_val))
                out_str = (
                    json.dumps(sanitized_out, sort_keys=True)
                    if isinstance(sanitized_out, (dict, list, tuple))
                    else str(sanitized_out)
                )
                scrubbed_out = scrub_text(out_str)[:max_output_chars]
                parts.append(f"output={scrubbed_out}")

            if ft_val is not None and ft_val != out_val:
                sanitized_ft = sanitize_data(copy.deepcopy(ft_val))
                ft_str = (
                    json.dumps(sanitized_ft, sort_keys=True)
                    if isinstance(sanitized_ft, (dict, list, tuple))
                    else str(sanitized_ft)
                )
                scrubbed_ft = scrub_text(ft_str)[:max_output_chars]
                if out_val is None:
                    parts.append(f"output={scrubbed_ft}")
                else:
                    parts.append(f"free_text={scrubbed_ft}")

            if err_val is not None and err_val != out_val and err_val != ft_val:
                sanitized_err = sanitize_data(copy.deepcopy(err_val))
                err_str = (
                    json.dumps(sanitized_err, sort_keys=True)
                    if isinstance(sanitized_err, (dict, list, tuple))
                    else str(sanitized_err)
                )
                scrubbed_err = scrub_text(err_str)[:max_output_chars]
                if out_val is None and ft_val is None:
                    parts.append(f"output={scrubbed_err}")
                else:
                    parts.append(f"error={scrubbed_err}")

            lines.append(" ".join(parts))
        elif isinstance(evt, Event):
            parts = [f"[{evt.seq}] {evt.type} action_id={evt.action_id}"]
            tool_field = evt.fields.get("tool")
            if tool_field is not None:
                parts.append(f"tool={tool_field.value}")
            args_field = evt.fields.get("arguments")
            if args_field is not None:
                sanitized_args = sanitize_data(copy.deepcopy(args_field.value))
                if isinstance(sanitized_args, dict):
                    parts.append(f"arguments={json.dumps(sanitized_args, sort_keys=True)}")
                else:
                    parts.append(f"arguments={sanitized_args}")
            if evt.decision:
                parts.append(f"decision={evt.decision.value}")
            if evt.free_text:
                scrubbed_ft = scrub_text(evt.free_text)[:max_output_chars]
                parts.append(f"output={scrubbed_ft}")
            lines.append(" ".join(parts))
    return "\n".join(lines)


def build_state_summary(
    state: SessionState,
    events: Sequence[Event | StateEventEnvelope],
) -> dict[str, Any]:
    """
    Builds allow-listed typed state summary for HybridMonitor projection.
    Contains only typed fields and event references; no labels, secrets, or oracle data.
    """
    event_refs = [evt.action_id for evt in events if hasattr(evt, "action_id") and evt.action_id]
    raw_summary = {
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
    sanitized: Any = sanitize_data(copy.deepcopy(raw_summary))
    if isinstance(sanitized, dict):
        return sanitized
    return raw_summary


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
    - Defensive deep copies of action, state summary, registry facts, goal, policy text.
    - Sensitive fields (tokens, API keys, credentials, raw secrets) are completely excluded.
    - Monitors cannot mutate authoritative action or state objects.
    - ActionOnly sees action + registry facts of named entities + goal + policy text.
    - Transcript adds text transcript of H_t.
    - Hybrid adds state_summary (typed fields + event refs).
    - Labels and scenario secrets never enter any view.
    """
    sanitized_args = sanitize_data(copy.deepcopy(action.arguments))
    action_copy = CanonicalAction(
        action_id=action.action_id,
        session_id=action.session_id,
        seq=action.seq,
        tool=action.tool,
        arguments=sanitized_args,
        action_hash=action.action_hash,
    )

    registry_facts = registry.get_facts_for_action(action.tool, action.arguments)
    sanitized_facts = sanitize_data(copy.deepcopy(registry_facts))

    sanitized_goal = sanitize_data(copy.deepcopy(goal)) if goal is not None else None
    policy_text_copy = copy.deepcopy(policy_text) if policy_text is not None else None

    transcript: Optional[str] = None
    state_summary: Optional[dict[str, Any]] = None

    m_lower = monitor_type.lower()
    if m_lower in ("transcript", "b5"):
        transcript = format_transcript(copy.deepcopy(history))
    elif m_lower in ("hybrid", "p1"):
        state_summary = build_state_summary(state, history)

    return MonitorView(
        monitor_id=monitor_type,
        action=action_copy,
        registry_facts=sanitized_facts,
        goal=sanitized_goal,
        policy_text=policy_text_copy,
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

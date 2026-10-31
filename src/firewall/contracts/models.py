"""
Shared Pydantic domain models for AI Agent Permission Firewall.
Contracts Version: 0.1.0
Source: 05_TECHNICAL_SPEC.md §3.2, 08_IMPLEMENTATION_ROADMAP.md Phase 1
"""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from firewall.contracts.enums import (
    Classification,
    ConfirmationLevel,
    Decision,
    MonitorVerdict,
    OutcomeContract,
    PolicyVerdict,
    Provenance,
    ReviewStatus,
    ScoreKind,
    Zone,
)

CONTRACTS_VERSION: str = "0.1.0"


class TaggedValue(BaseModel):
    """Value with provenance tracking to enforce INV-07."""

    value: Any
    provenance: Provenance
    model_config = ConfigDict(extra="forbid")


class ResourceRef(BaseModel):
    """Reference to a selected resource with classification."""

    ref: str
    classification: Classification
    selected_seq: int
    model_config = ConfigDict(extra="forbid")


class DestinationRef(BaseModel):
    """Reference to an export destination with zone."""

    ref: str
    zone: Zone
    model_config = ConfigDict(extra="forbid")


class ExportJob(BaseModel):
    """Specification of an export job."""

    job_id: str
    resource_refs: list[str]
    destination_ref: str
    zone: Zone
    created_seq: int
    model_config = ConfigDict(extra="forbid")


class EgressCounter(BaseModel):
    """Cumulative egress counters per zone."""

    rows: int = 0
    bytes: int = 0
    rows_plus_pending: int = 0
    model_config = ConfigDict(extra="forbid")


class ActionRequest(BaseModel):
    """Untrusted action request submitted by the agent."""

    schema_version: str = CONTRACTS_VERSION
    session_id: str
    tool: str
    arguments: dict[str, Any]
    declared_intent: Optional[str] = None
    model_config = ConfigDict(extra="forbid")


class CanonicalAction(BaseModel):
    """Server-assigned canonical action with monotonic sequence and hash."""

    action_id: str
    session_id: str
    seq: int
    tool: str
    arguments: dict[str, Any]
    action_hash: str
    model_config = ConfigDict(extra="forbid")


class Event(BaseModel):
    """Event element in session history H_t."""

    event_id: str
    session_id: str
    seq: int
    type: str
    action_id: str
    fields: dict[str, TaggedValue] = Field(default_factory=dict)
    free_text: Optional[str] = None
    decision: Optional[Decision] = None
    model_config = ConfigDict(extra="forbid")


class SessionState(BaseModel):
    """Observable security state S_t."""

    state_version: str = CONTRACTS_VERSION
    head_hash: str
    seq: int = 0
    bound_resource: Optional[ResourceRef] = None
    selected_resources: list[ResourceRef] = Field(default_factory=list)
    jobs: dict[str, ExportJob] = Field(default_factory=dict)
    destination: Optional[DestinationRef] = None
    job_created: bool = False
    egress_counters: dict[str, EgressCounter] = Field(default_factory=dict)
    anomalies: list[str] = Field(default_factory=list)
    indeterminate_state: int = 0
    model_config = ConfigDict(extra="forbid")


class PolicyResult(BaseModel):
    """Outcome of deterministic policy evaluation."""

    verdict: PolicyVerdict
    matched_rules: list[str] = Field(default_factory=list)
    maybe_rules: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    policy_hash: str
    registry_hash: str
    model_config = ConfigDict(extra="forbid")


class MonitorView(BaseModel):
    """Allow-listed information projection provided to monitors."""

    monitor_id: str
    action: CanonicalAction
    registry_facts: dict[str, Any] = Field(default_factory=dict)
    goal: Optional[dict[str, Any]] = None
    policy_text: Optional[str] = None
    transcript: Optional[str] = None
    state_summary: Optional[dict[str, Any]] = None
    model_config = ConfigDict(extra="forbid")


class MonitorAssessment(BaseModel):
    """Advisory assessment returned by an execution monitor."""

    verdict: MonitorVerdict
    score: Optional[float] = None
    score_kind: ScoreKind = ScoreKind.NONE
    rationale: Optional[str] = None
    raw_output: Optional[str] = None
    model_id: Optional[str] = None
    prompt_hash: Optional[str] = None
    monitor_version: str
    latency_ms: float = 0.0
    error: Optional[str] = None
    model_config = ConfigDict(extra="forbid", protected_namespaces=())


class VersionSet(BaseModel):
    """Set of component and config hashes active for a decision."""

    contracts: str = CONTRACTS_VERSION
    policy_hash: str
    registry_hash: str
    monitor_version: str = "none"
    prompt_hash: Optional[str] = None
    firewall_config_hash: str
    model_config = ConfigDict(extra="forbid")


class DecisionRecord(BaseModel):
    """Immutable audit record of a firewall authorization decision."""

    decision_id: str
    action_id: str
    action_hash: str
    state_head_hash: str
    decision: Decision
    reason_codes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    policy_verdict: PolicyVerdict
    monitor_verdict: MonitorVerdict = MonitorVerdict.NOT_CONSULTED
    versions: VersionSet
    timings_ms: dict[str, float] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")


class AuthorizationToken(BaseModel):
    """Cryptographic authorization token authorizing tool execution."""

    token_id: str
    action_id: str
    action_hash: str
    state_head_hash: str
    decision_id: str
    nonce: str
    expires_at_ms: int
    model_config = ConfigDict(extra="forbid")


class ReviewerView(BaseModel):
    """Allow-listed summary presented to a human reviewer."""

    tool: str
    typed_arguments: dict[str, Any]
    policy_verdict: PolicyVerdict
    reason_codes: list[str] = Field(default_factory=list)
    state_facts: dict[str, Any] = Field(default_factory=dict)
    monitor_assessment: Optional[MonitorAssessment] = None
    model_config = ConfigDict(extra="forbid")


class ReviewTicket(BaseModel):
    """Review ticket for actions requiring human oversight."""

    ticket_id: str
    action_id: str
    action_hash: str
    created_ms: int
    expires_ms: int
    status: ReviewStatus = ReviewStatus.PENDING
    summary: ReviewerView
    resolved_by: Optional[str] = None
    resolved_ms: Optional[int] = None
    model_config = ConfigDict(extra="forbid")


class ResultEnvelope(BaseModel):
    """Standardized result envelope for execution outcomes."""

    has_value: bool
    value: Optional[Any] = None
    error: Optional[dict[str, str]] = None
    outcome_contract: OutcomeContract
    confirmation_level: ConfirmationLevel
    model_config = ConfigDict(extra="forbid")


class StateEventEnvelope(BaseModel):
    """Canonical envelope for hash-chained state transitions."""

    session_id: str
    seq: int
    prior_head: str
    event_type: str
    action_id: str
    token_id: str
    payload: dict[str, Any]
    model_config = ConfigDict(extra="forbid")


class EvidenceReceipt(BaseModel):
    """Cryptographically verifiable evidence receipt from trusted executor."""

    session_id: str
    action_id: str
    token_id: str
    source_tool_name: str
    observed_state: dict[str, Any]
    observed_timestamp_ms: int
    signature: str
    model_config = ConfigDict(extra="forbid")

"""
Shared enumeration types for the AI Agent Permission Firewall.
Contracts Version: 0.1.0
Source: 05_TECHNICAL_SPEC.md §3.1
"""

from enum import Enum


class Decision(str, Enum):
    """Final gateway / decision function outcome."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"


class PolicyVerdict(str, Enum):
    """Deterministic three-valued policy engine evaluation verdict."""
    PROHIBIT = "PROHIBIT"
    PERMIT = "PERMIT"
    UNDETERMINED = "UNDETERMINED"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"


class MonitorVerdict(str, Enum):
    """Advisory assessment verdict returned by an execution monitor."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"
    NOT_CONSULTED = "NOT_CONSULTED"


class ScoreKind(str, Enum):
    """Semantics of monitor risk scores."""
    NONE = "NONE"
    HEURISTIC_RISK = "HEURISTIC_RISK"
    MODEL_PROBABILITY_UNCALIBRATED = "MODEL_PROBABILITY_UNCALIBRATED"
    MODEL_PROBABILITY_CALIBRATED = "MODEL_PROBABILITY_CALIBRATED"
    MODEL_VERBALIZED_CONFIDENCE = "MODEL_VERBALIZED_CONFIDENCE"


class ToolClass(str, Enum):
    """Sensitivity class assigned to registered tools in config/registry.yaml."""
    READ_LOW = "READ_LOW"
    READ_SENSITIVE = "READ_SENSITIVE"
    WRITE_INTERNAL = "WRITE_INTERNAL"
    EGRESS_EXTERNAL = "EGRESS_EXTERNAL"
    DESTRUCTIVE = "DESTRUCTIVE"
    PRIVILEGED_ADMIN = "PRIVILEGED_ADMIN"


class Classification(str, Enum):
    """Data sensitivity classification for resources."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    UNKNOWN = "UNKNOWN"


class Zone(str, Enum):
    """Destination network/storage zones."""
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


class Provenance(str, Enum):
    """Attestation source for field values in state tracking."""
    GATEWAY = "GATEWAY"
    REGISTRY = "REGISTRY"
    TOOL_TYPED = "TOOL_TYPED"
    TOOL_FREETEXT = "TOOL_FREETEXT"
    AGENT_CLAIM = "AGENT_CLAIM"


class ExecStatus(str, Enum):
    """Terminal outcome of tool execution."""
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    EXEC_UNKNOWN = "EXEC_UNKNOWN"
    NOT_EXECUTED = "NOT_EXECUTED"


class OutcomeContract(str, Enum):
    """Declared execution outcome contract from tool specification."""
    SYNCHRONOUS_CONFIRMED = "SYNCHRONOUS_CONFIRMED"
    ACCEPTED_ASYNC = "ACCEPTED_ASYNC"
    BEST_EFFORT_DISPATCH = "BEST_EFFORT_DISPATCH"


class ConfirmationLevel(str, Enum):
    """Level of external effect confirmation verified for an execution outcome."""
    CONFIRMED_COMPLETED = "CONFIRMED_COMPLETED"
    DISPATCH_ACKNOWLEDGED = "DISPATCH_ACKNOWLEDGED"
    ATTEMPTED_DISPATCH = "ATTEMPTED_DISPATCH"
    NONE = "NONE"


class ReviewStatus(str, Enum):
    """Status of human oversight review tickets."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"
    STALE = "STALE"


class EventType(str, Enum):
    """Lifecycle event types recorded in session history."""
    ACTION_RECEIVED = "ACTION_RECEIVED"
    ACTION_DENIED = "ACTION_DENIED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    EXEC_UNKNOWN = "EXEC_UNKNOWN"
    REVIEW_RESOLVED = "REVIEW_RESOLVED"
    EVIDENCE_SYNC = "EVIDENCE_SYNC"
    ADMIN_RECONCILE = "ADMIN_RECONCILE"


class Anomaly(str, Enum):
    """State anomaly flags detected during session state folding."""
    CONFLICTING_SELECTION = "CONFLICTING_SELECTION"
    UNKNOWN_CLASSIFICATION = "UNKNOWN_CLASSIFICATION"
    UNKNOWN_DESTINATION = "UNKNOWN_DESTINATION"

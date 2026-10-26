"""
State tracking and observable views package for AI Agent Permission Firewall.
Contracts Version: 0.1.0
Source: 05_TECHNICAL_SPEC.md §8, 08_IMPLEMENTATION_ROADMAP.md Phase 4
"""

from firewall.state.engine import (
    BindingMode,
    apply_event,
    compute_state_head,
    initial_state,
    replay_events,
)
from firewall.state.errors import (
    EvidenceVerificationError,
    StateContinuityError,
    StateError,
    StateIntegrityError,
    StateTransitionError,
)
from firewall.state.evidence import (
    EvidenceVerifier,
    HmacEvidenceVerifier,
)
from firewall.state.registry import (
    DestinationInfo,
    Registry,
    ResourceInfo,
    ToolInfo,
    load_registry_from_yaml,
    load_test_registry,
)
from firewall.state.views import (
    PolicyView,
    build_monitor_view,
    build_policy_view,
    build_reviewer_view,
    build_state_summary,
    format_transcript,
)

__all__ = [
    # Engine
    "BindingMode",
    "initial_state",
    "apply_event",
    "replay_events",
    "compute_state_head",
    # Evidence & Verification
    "EvidenceVerifier",
    "HmacEvidenceVerifier",
    # Errors
    "StateError",
    "StateContinuityError",
    "StateIntegrityError",
    "StateTransitionError",
    "EvidenceVerificationError",
    # Registry
    "Registry",
    "ResourceInfo",
    "DestinationInfo",
    "ToolInfo",
    "load_test_registry",
    "load_registry_from_yaml",
    # Views
    "PolicyView",
    "build_policy_view",
    "build_monitor_view",
    "build_reviewer_view",
    "build_state_summary",
    "format_transcript",
]

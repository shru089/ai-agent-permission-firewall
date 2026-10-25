"""
State Engine exceptions for AI Agent Permission Firewall.
Enforces sequence integrity, prior-head continuity, and state transition validity.
Source: 05_TECHNICAL_SPEC.md §8, §10
"""


class StateError(Exception):
    """Base exception for all state engine errors."""


class StateContinuityError(StateError):
    """
    Raised when session identity, monotonic sequence order, or prior-head continuity
    fails validation (INV-02, INV-06, INV-12).
    """


class StateIntegrityError(StateError):
    """
    Raised when an event envelope, payload, or cryptographic hash chain
    is corrupted or fails validation (INV-09).
    """


class StateTransitionError(StateError):
    """
    Raised when a state transition cannot be executed deterministically.
    """

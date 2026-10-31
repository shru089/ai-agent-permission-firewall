"""
Rejection-cascade integration package for the AI Agent Permission Firewall.
Version: 0.1.0
Source: 05_TECHNICAL_SPEC.md §9, 06_EXPERIMENT_PROTOCOL.md §2
"""

from firewall.cascade.adapter import (
    CascadeAdapter,
    CascadeDecision,
    CascadeFailureReason,
)

__all__ = ["CascadeAdapter", "CascadeDecision", "CascadeFailureReason"]

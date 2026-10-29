"""
Deterministic Policy Engine package (C3) for AI Agent Permission Firewall.
Source: 05_TECHNICAL_SPEC.md §7.2, 03_MATHEMATICAL_MODEL_AND_METRICS.md §3
"""

from firewall.policy.evaluator import PolicyEngine, create_default_stateful_policy
from firewall.policy.rules import Condition, PolicyRule, TriBool

__all__ = [
    "PolicyEngine",
    "create_default_stateful_policy",
    "Condition",
    "PolicyRule",
    "TriBool",
]

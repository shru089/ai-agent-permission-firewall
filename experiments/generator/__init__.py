"""
Deterministic Scenario Generator Package (C10/C11).

Provides reproducible generation of multi-step agent traces for benchmark evaluation.
Enforces Action-D invariance (T-EXP-002), split disjointness (T-EXP-005), and provenance tracking.
"""

from experiments.generator.pairing import ActionDInvarianceChecker, PairedTraceMatch
from experiments.generator.scenarios import (
    ALL_TEMPLATES,
    CAL_TEMPLATES,
    DEV_TEMPLATES,
    TEST_IN_TEMPLATES,
    TEST_NOVEL_TEMPLATES,
    ScenarioTemplate,
)
from experiments.generator.trace_builder import TraceBuilder

__all__ = [
    "ALL_TEMPLATES",
    "ActionDInvarianceChecker",
    "CAL_TEMPLATES",
    "DEV_TEMPLATES",
    "PairedTraceMatch",
    "ScenarioTemplate",
    "TEST_IN_TEMPLATES",
    "TEST_NOVEL_TEMPLATES",
    "TraceBuilder",
]

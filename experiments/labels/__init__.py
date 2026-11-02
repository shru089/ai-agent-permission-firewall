"""
Independent Label Oracle Package (C10/C11).

Provides specification-level ground-truth evaluation for AI agent permission traces.
Enforces INV-08 and T-EXP-009: strictly independent from runtime firewall policy evaluation.
"""

from experiments.labels.oracle import (
    OracleLabelResult,
    SpecificationLabelOracle,
)
from experiments.labels.rules import (
    OracleRule,
    OracleVerdict,
)

__all__ = [
    "OracleLabelResult",
    "OracleRule",
    "OracleVerdict",
    "SpecificationLabelOracle",
]

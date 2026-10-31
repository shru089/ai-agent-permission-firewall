"""
Validation and Evaluation-Handoff Quality Gate Package.

Provides automated acceptance validators for:
1. H1 manipulation-check acceptance (docs/06_EXPERIMENT_PROTOCOL.md §2.2).
2. End-to-end information barrier and anti-leakage audit (INV-08).
"""

from experiments.validation.h1_manipulation_check import (
    H1ManipulationCheckValidator,
    H1ValidationResult,
    H1ValidationStatus,
)
from experiments.validation.information_barrier import (
    InformationBarrierAuditResult,
    InformationBarrierValidator,
)

__all__ = [
    "H1ManipulationCheckValidator",
    "H1ValidationResult",
    "H1ValidationStatus",
    "InformationBarrierAuditResult",
    "InformationBarrierValidator",
]

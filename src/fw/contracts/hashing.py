"""
Canonical contracts hashing (src/fw/contracts/hashing.py per 05_TECHNICAL_SPEC.md §4).
"""

from firewall.contracts.hashing import (
    canonical_hash,
    canonical_json,
    compute_action_hash,
    compute_genesis_head,
)

__all__ = [
    "canonical_json",
    "canonical_hash",
    "compute_action_hash",
    "compute_genesis_head",
]

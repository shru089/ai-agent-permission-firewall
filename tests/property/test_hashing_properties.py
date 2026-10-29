"""
Property-based tests for canonical hashing (T-GW-006) using Hypothesis.
Source: 05_TECHNICAL_SPEC.md §4, §13 (T-GW-006)
"""

import random
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from firewall.contracts.hashing import canonical_hash, canonical_json, compute_action_hash

# Recursive strategy for JSON objects with no floats
json_primitives = (
    st.none() | st.booleans() | st.integers(min_value=-(10**9), max_value=10**9) | st.text()
)
json_values = st.recursive(
    json_primitives,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(), children, max_size=5)
    ),
    max_leaves=25,
)


def _shuffle_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively shuffles dict key insertion order."""
    keys = list(d.keys())
    random.shuffle(keys)
    result: dict[str, Any] = {}
    for k in keys:
        v = d[k]
        if isinstance(v, dict):
            result[k] = _shuffle_dict(v)
        elif isinstance(v, list):
            result[k] = [_shuffle_dict(x) if isinstance(x, dict) else x for x in v]
        else:
            result[k] = v
    return result


@pytest.mark.property
@given(
    session_id=st.text(min_size=1, max_size=20),
    seq=st.integers(min_value=1, max_value=10000),
    tool=st.text(min_size=1, max_size=20),
    args=st.dictionaries(st.text(min_size=1, max_size=10), json_values, max_size=5),
)
def test_action_hash_permutation_invariance_property(
    session_id: str, seq: int, tool: str, args: dict[str, Any]
) -> None:
    """Hypothesis property: Permuting dictionary key order never alters action_hash."""
    hash_original = compute_action_hash(session_id, seq, tool, args)
    shuffled_args = _shuffle_dict(args)
    hash_shuffled = compute_action_hash(session_id, seq, tool, shuffled_args)
    assert hash_original == hash_shuffled


@pytest.mark.property
@given(data=st.dictionaries(st.text(min_size=1, max_size=10), json_values, max_size=5))
def test_canonical_json_permutation_invariance_property(data: dict[str, Any]) -> None:
    """Hypothesis property: Canonical JSON bytes are strictly invariant to key insertion order."""
    bytes_original = canonical_json(data)
    shuffled = _shuffle_dict(data)
    bytes_shuffled = canonical_json(shuffled)
    assert bytes_original == bytes_shuffled
    assert canonical_hash(data) == canonical_hash(shuffled)

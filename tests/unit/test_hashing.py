"""
Tests for canonical JSON serialization and action hashing (T-GW-006).
Source: 05_TECHNICAL_SPEC.md §4, §13 (T-GW-006)
"""

import pytest

from firewall.contracts import (
    canonical_hash,
    canonical_json,
    compute_action_hash,
    compute_genesis_head,
)


@pytest.mark.unit
def test_tgw_006_key_order_stability() -> None:
    """T-GW-006: Canonical action hash is invariant to key order in arguments."""
    args1 = {"destination": "archive", "format": "csv", "count": 100}
    args2 = {"count": 100, "destination": "archive", "format": "csv"}
    args3 = {"format": "csv", "count": 100, "destination": "archive"}

    hash1 = compute_action_hash("sess_001", 1, "export_data", args1)
    hash2 = compute_action_hash("sess_001", 1, "export_data", args2)
    hash3 = compute_action_hash("sess_001", 1, "export_data", args3)

    assert hash1 == hash2 == hash3


@pytest.mark.unit
def test_tgw_006_nested_key_order_stability() -> None:
    """T-GW-006: Invariance to key order in deeply nested dictionaries."""
    args1 = {"config": {"b": 2, "a": 1, "nested": {"z": 26, "y": 25}}}
    args2 = {"config": {"nested": {"y": 25, "z": 26}, "a": 1, "b": 2}}

    hash1 = compute_action_hash("sess_001", 1, "nested_tool", args1)
    hash2 = compute_action_hash("sess_001", 1, "nested_tool", args2)

    assert hash1 == hash2


@pytest.mark.unit
def test_tgw_006_unicode_normalization_stability() -> None:
    """T-GW-006: Invariance under Unicode NFC normalization."""
    # Precomposed é (\u00e9) vs decomposed e + acute accent (e\u0301)
    precomposed = "caf\u00e9"
    decomposed = "cafe\u0301"
    assert precomposed != decomposed  # raw string bytes differ

    hash_precomposed = compute_action_hash("sess_001", 1, "tool", {"name": precomposed})
    hash_decomposed = compute_action_hash("sess_001", 1, "tool", {"name": decomposed})

    assert hash_precomposed == hash_decomposed

    # In session_id and tool name as well
    hash_tool1 = compute_action_hash(decomposed, 1, precomposed, {"k": "v"})
    hash_tool2 = compute_action_hash(precomposed, 1, decomposed, {"k": "v"})
    assert hash_tool1 == hash_tool2


@pytest.mark.unit
def test_tgw_006_floats_rejected_in_arguments() -> None:
    """05 §4: Floating-point numbers are strictly rejected in arguments."""
    with pytest.raises(ValueError, match="Floating-point numbers are prohibited"):
        compute_action_hash("sess_001", 1, "tool", {"float_val": 1.25})

    with pytest.raises(ValueError, match="Floating-point numbers are prohibited"):
        compute_action_hash("sess_001", 1, "tool", {"nested": [1, 2, 3.14]})


@pytest.mark.unit
def test_action_hash_sensitivity() -> None:
    """Changing any element of the preimage alters the action hash."""
    base_hash = compute_action_hash("sess_001", 1, "export_tool", {"arg": "val"})

    assert compute_action_hash("sess_002", 1, "export_tool", {"arg": "val"}) != base_hash
    assert compute_action_hash("sess_001", 2, "export_tool", {"arg": "val"}) != base_hash
    assert compute_action_hash("sess_001", 1, "other_tool", {"arg": "val"}) != base_hash
    assert (
        compute_action_hash("sess_001", 1, "export_tool", {"arg": "val"}, version="0.2.0")
        != base_hash
    )


@pytest.mark.unit
def test_genesis_head_computation() -> None:
    head1 = compute_genesis_head("sess_001")
    head2 = compute_genesis_head("sess_001")
    head3 = compute_genesis_head("sess_002")

    assert head1 == head2
    assert head1 != head3
    assert len(head1) == 64


@pytest.mark.unit
def test_rfc8785_canonical_bytes() -> None:
    """RFC 8785 serialization produces compact UTF-8 without extra spaces."""
    data = {"b": "two", "a": 1, "c": [3, 2, 1]}
    c_bytes = canonical_json(data)
    assert c_bytes == b'{"a":1,"b":"two","c":[3,2,1]}'
    assert canonical_hash(data) == canonical_hash({"c": [3, 2, 1], "b": "two", "a": 1})

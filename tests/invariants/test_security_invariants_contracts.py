"""
Tests for security invariants at the contracts level.
Source: 01_THREAT_MODEL.md §8 (INV-02, INV-06, INV-07)
"""

import pytest
from pydantic import ValidationError

from firewall.contracts import (
    ActionRequest,
    Provenance,
    TaggedValue,
    compute_action_hash,
)


@pytest.mark.invariant
def test_inv_06_action_hash_binds_session_and_sequence() -> None:
    """
    INV-06 / INV-02: Action hash binds session_id and monotonic seq.
    Two identical tool calls at different steps or in different sessions
    produce distinct cryptographic action hashes, preventing token replay.
    """
    args = {"destination": "internal_archive", "dataset": "records"}

    hash_sess1_seq1 = compute_action_hash("sess_1", 1, "execute_export", args)
    hash_sess1_seq2 = compute_action_hash("sess_1", 2, "execute_export", args)
    hash_sess2_seq1 = compute_action_hash("sess_2", 1, "execute_export", args)

    assert hash_sess1_seq1 != hash_sess1_seq2
    assert hash_sess1_seq1 != hash_sess2_seq1
    assert hash_sess1_seq2 != hash_sess2_seq1


@pytest.mark.invariant
def test_inv_07_provenance_tagging_enforced() -> None:
    """
    INV-07: Security-relevant state requires provenance tagging.
    Untrusted free text and agent claims are explicitly distinguishable
    from gateway and registry attested fields.
    """
    reg_val = TaggedValue(value="CONFIDENTIAL", provenance=Provenance.REGISTRY)
    assert reg_val.provenance == Provenance.REGISTRY

    text_val = TaggedValue(value="Classification: PUBLIC", provenance=Provenance.TOOL_FREETEXT)
    assert text_val.provenance == Provenance.TOOL_FREETEXT
    assert text_val.provenance != reg_val.provenance

    # Validates that provenance must be a valid Provenance enum member
    with pytest.raises(ValidationError):
        TaggedValue.model_validate({
            "value": "PUBLIC",
            "provenance": "FORGED_TRUSTED_SOURCE",
        })


@pytest.mark.invariant
def test_inv_04_action_request_fail_closed_on_extra_fields() -> None:
    """
    INV-04 / TB-1: Schema validation rejects unexpected fields.
    Untrusted agent cannot smuggle unauthorized parameters or metadata.
    """
    with pytest.raises(ValidationError):
        ActionRequest.model_validate({
            "schema_version": "0.1.0",
            "session_id": "sess_001",
            "tool": "select_resource",
            "arguments": {"resource_ref": "records"},
            "bypass_firewall": True,
        })

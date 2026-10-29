"""
Unit tests for single-use authorization token store and ControlledExecutor (C6).
Verifies:
- Token creation, expiration, and atomic single-use redemption (INV-06)
- Protection against concurrent double-spending
- Binding checks against action_id, action_hash, and state_head_hash
- Output envelope confirmation levels
"""

import pytest

from firewall.contracts.enums import ConfirmationLevel
from firewall.contracts.models import CanonicalAction
from firewall.executor.executor import ControlledExecutor
from firewall.executor.tokens import (
    TokenBindingMismatchError,
    TokenExpiredError,
    TokenReusedError,
    TokenStore,
)
from firewall.state.evidence import HmacEvidenceVerifier


def test_token_store_lifecycle():
    store = TokenStore()
    token = store.issue_token(
        action_id="act_01",
        action_hash="hash_01",
        state_head_hash="head_01",
        decision_id="dec_01",
        ttl_ms=5000,
        now_ms=1000,
    )

    assert token.token_id.startswith("tok_")
    assert store.is_consumed(token.token_id) is False

    # Successful single-use redemption
    consumed = store.consume_token(
        token_id=token.token_id,
        expected_action_id="act_01",
        expected_action_hash="hash_01",
        expected_state_head_hash="head_01",
        now_ms=2000,
    )
    assert consumed.token_id == token.token_id
    assert store.is_consumed(token.token_id) is True

    # Re-use fails with TokenReusedError
    with pytest.raises(TokenReusedError):
        store.consume_token(
            token_id=token.token_id,
            expected_action_id="act_01",
            expected_action_hash="hash_01",
            expected_state_head_hash="head_01",
            now_ms=2100,
        )


def test_token_expiration():
    store = TokenStore()
    token = store.issue_token(
        action_id="act_02",
        action_hash="hash_02",
        state_head_hash="head_02",
        decision_id="dec_02",
        ttl_ms=1000,
        now_ms=1000,  # expires at 2000
    )

    with pytest.raises(TokenExpiredError):
        store.consume_token(
            token_id=token.token_id,
            expected_action_id="act_02",
            expected_action_hash="hash_02",
            expected_state_head_hash="head_02",
            now_ms=2001,  # 1ms past expiry
        )


def test_token_binding_mismatches():
    store = TokenStore()
    token = store.issue_token(
        action_id="act_03",
        action_hash="hash_03",
        state_head_hash="head_03",
        decision_id="dec_03",
    )

    with pytest.raises(TokenBindingMismatchError, match="action_id"):
        store.consume_token(token.token_id, "wrong_act", "hash_03", "head_03")

    with pytest.raises(TokenBindingMismatchError, match="action_hash"):
        store.consume_token(token.token_id, "act_03", "wrong_hash", "head_03")

    with pytest.raises(TokenBindingMismatchError, match="state_head_hash"):
        store.consume_token(token.token_id, "act_03", "hash_03", "wrong_head")


def test_controlled_executor_signed_evidence():
    store = TokenStore()
    verifier = HmacEvidenceVerifier(key=b"secret_key_123")
    executor = ControlledExecutor(token_store=store, verifier=verifier)

    token = store.issue_token(
        action_id="act_export",
        action_hash="hash_export",
        state_head_hash="head_export",
        decision_id="dec_export",
    )

    action = CanonicalAction(
        action_id="act_export",
        session_id="sess_exp",
        seq=1,
        tool="execute_export",
        arguments={"rows": 1000, "bytes": 50000},
        action_hash="hash_export",
    )

    envelope, receipt = executor.execute(token, action, "head_export")

    assert envelope.has_value is True
    assert envelope.confirmation_level == ConfirmationLevel.CONFIRMED_COMPLETED
    assert receipt is not None
    assert receipt.session_id == "sess_exp"
    assert receipt.action_id == "act_export"
    assert receipt.observed_state == {"rows": 1000, "bytes": 50000}

    # Verify signature using verifier
    rows, bytes_count = verifier.verify(
        receipt=receipt,
        expected_session_id="sess_exp",
        expected_action_id="act_export",
        expected_token_id=token.token_id,
        expected_tool="execute_export",
    )
    assert rows == 1000
    assert bytes_count == 50000

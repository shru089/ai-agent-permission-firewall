"""
Single-use authorization token store and atomic lifecycle manager (C6).
Enforces INV-06: Tokens are single-use and bound to session, action, and state head.
Source: 05_TECHNICAL_SPEC.md §3.2, §4, 01_THREAT_MODEL.md (INV-06)
"""

import threading
import time
import uuid
from typing import Optional

from firewall.contracts.models import AuthorizationToken


class TokenError(Exception):
    """Base exception for authorization token errors."""


class TokenNotFoundError(TokenError):
    """Raised when token ID does not exist in store."""


class TokenReusedError(TokenError):
    """Raised when token was already redeemed / consumed (INV-06)."""


class TokenExpiredError(TokenError):
    """Raised when token is redeemed after its expiration timestamp."""


class TokenBindingMismatchError(TokenError):
    """Raised when token action_id, action_hash, or state_head_hash does not match."""


class TokenStore:
    """
    Thread-safe, atomic single-use authorization token store.
    Guarantees:
    - Atomic check-and-consume preventing concurrent double-spending (INV-06).
    - Cryptographic binding to action_id, action_hash, and state_head_hash.
    - Expiration enforcement.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: dict[str, AuthorizationToken] = {}
        self._consumed: set[str] = set()

    def issue_token(
        self,
        action_id: str,
        action_hash: str,
        state_head_hash: str,
        decision_id: str,
        ttl_ms: int = 60_000,
        now_ms: Optional[int] = None,
    ) -> AuthorizationToken:
        """Issue and record a fresh authorization token."""
        curr_time = now_ms if now_ms is not None else int(time.time() * 1000)
        token_id = f"tok_{uuid.uuid4().hex[:12]}"
        nonce = uuid.uuid4().hex

        token = AuthorizationToken(
            token_id=token_id,
            action_id=action_id,
            action_hash=action_hash,
            state_head_hash=state_head_hash,
            decision_id=decision_id,
            nonce=nonce,
            expires_at_ms=curr_time + ttl_ms,
        )

        with self._lock:
            self._tokens[token_id] = token

        return token

    def consume_token(
        self,
        token_id: str,
        expected_action_id: str,
        expected_action_hash: str,
        expected_state_head_hash: str,
        now_ms: Optional[int] = None,
    ) -> AuthorizationToken:
        """
        Atomically validate and consume a single-use authorization token.
        Raises TokenError on any validation or double-spend attempt.
        """
        curr_time = now_ms if now_ms is not None else int(time.time() * 1000)

        with self._lock:
            # 1. Check existence
            token = self._tokens.get(token_id)
            if token is None:
                raise TokenNotFoundError(f"Token '{token_id}' not found in store")

            # 2. Check single-use / already consumed (INV-06)
            if token_id in self._consumed:
                raise TokenReusedError(
                    f"Token '{token_id}' has already been consumed (single-use violation)"
                )

            # 3. Check expiration
            if curr_time > token.expires_at_ms:
                raise TokenExpiredError(
                    f"Token '{token_id}' expired at {token.expires_at_ms} (now: {curr_time})"
                )

            # 4. Check action binding
            if token.action_id != expected_action_id:
                raise TokenBindingMismatchError(
                    f"Token action_id mismatch: expected '{expected_action_id}', "
                    f"got '{token.action_id}'"
                )

            # 5. Check action hash binding
            if token.action_hash != expected_action_hash:
                raise TokenBindingMismatchError(
                    f"Token action_hash mismatch: expected '{expected_action_hash}', "
                    f"got '{token.action_hash}'"
                )

            # 6. Check state head hash binding (stale-decision / TOCTOU check)
            if token.state_head_hash != expected_state_head_hash:
                raise TokenBindingMismatchError(
                    f"Token state_head_hash mismatch: expected '{expected_state_head_hash}', "
                    f"got '{token.state_head_hash}'"
                )

            # Atomically mark consumed
            self._consumed.add(token_id)
            return token

    def is_consumed(self, token_id: str) -> bool:
        """Check whether a token has been consumed."""
        with self._lock:
            return token_id in self._consumed

"""
Evidence verification module for AI Agent Permission Firewall (SEC-01, SEC-02).
Provides cryptographic authentication, authoritative session/action/token/tool binding checks,
observation schema validation, and replay protection for execution evidence receipts.

Source: 05_TECHNICAL_SPEC.md §8, 01_THREAT_MODEL.md (INV-07, INV-08, INV-12),
        SEC_01_02_REMEDIATION_DESIGN.md (D-33, D-34, D-35)
"""

import hashlib
import hmac
from typing import Any, Optional, Protocol, runtime_checkable

from firewall.contracts.hashing import canonical_json
from firewall.contracts.models import EvidenceReceipt
from firewall.state.errors import EvidenceVerificationError


@runtime_checkable
class EvidenceVerifier(Protocol):
    """
    Protocol for execution evidence receipt verification (D-33).
    Decouples cryptographic verification and schema validation from the state transition fold.
    """

    def verify(
        self,
        receipt: EvidenceReceipt,
        expected_session_id: str,
        expected_action_id: str,
        expected_token_id: str,
        expected_tool: str,
        token_expires_at_ms: Optional[int] = None,
        now_ms: Optional[int] = None,
        is_replay: bool = False,
    ) -> tuple[int, int]:
        """
        Verifies evidence authenticity, cryptographic MAC, authoritative bindings,
        observation schema, freshness, and replay protection.

        Returns:
            tuple[int, int]: Validated (rows, bytes) count.

        Raises:
            EvidenceVerificationError: On any validation or authentication failure.
        """
        ...


class HmacEvidenceVerifier:
    """
    HMAC-SHA256 evidence receipt verifier for single-process MVP architecture (D-33).

    Trust and Security Assumptions:
    - Host and single-process Python runtime are trusted (A-03, 01_THREAT_MODEL.md §9).
    - Private Python attributes (_key) provide structural encapsulation, not a memory-level
      isolation boundary against untrusted in-process code (SEC_01_02_REMEDIATION_DESIGN.md §7).
    - Agent-controlled code and drivers run strictly sandboxed (C10) and cannot access memory.
    - Symmetric HMAC authenticates that receipt was constructed by entity possessing secret key.
    - Symmetrical HMAC provides zero cryptographic isolation between Gateway and Executor
      in-process; migration to asymmetric Ed25519 is mandated when Executor moves out-of-process.
    - Local hash chaining and HMAC do not protect against wholesale database rewriting (OQ-23);
      external tamper-evident anchoring is required for long-term audit store integrity.
    """

    def __init__(self, key: bytes | str) -> None:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if not key:
            raise ValueError("HMAC key must not be empty")
        self._key: bytes = key
        self._seen_receipts: set[str] = set()

    def compute_signature(self, receipt_data: dict[str, Any] | EvidenceReceipt) -> str:
        """
        Computes HMAC-SHA256 signature over RFC 8785 canonical JSON preimage
        of authenticated receipt fields.
        """
        if isinstance(receipt_data, EvidenceReceipt):
            data = {
                "action_id": receipt_data.action_id,
                "observed_state": receipt_data.observed_state,
                "observed_timestamp_ms": receipt_data.observed_timestamp_ms,
                "session_id": receipt_data.session_id,
                "source_tool_name": receipt_data.source_tool_name,
                "token_id": receipt_data.token_id,
            }
        else:
            data = {
                "action_id": receipt_data["action_id"],
                "observed_state": receipt_data["observed_state"],
                "observed_timestamp_ms": receipt_data["observed_timestamp_ms"],
                "session_id": receipt_data["session_id"],
                "source_tool_name": receipt_data["source_tool_name"],
                "token_id": receipt_data["token_id"],
            }
        canonical_bytes = canonical_json(data, reject_floats=False)
        return hmac.new(self._key, canonical_bytes, hashlib.sha256).hexdigest()

    def create_signed_receipt(
        self,
        session_id: str,
        action_id: str,
        token_id: str,
        source_tool_name: str,
        observed_state: dict[str, Any],
        observed_timestamp_ms: int = 1000,
    ) -> EvidenceReceipt:
        """Helper to create a legitimate, cryptographically signed EvidenceReceipt."""
        data = {
            "action_id": action_id,
            "observed_state": observed_state,
            "observed_timestamp_ms": observed_timestamp_ms,
            "session_id": session_id,
            "source_tool_name": source_tool_name,
            "token_id": token_id,
        }
        sig = self.compute_signature(data)
        return EvidenceReceipt(
            session_id=session_id,
            action_id=action_id,
            token_id=token_id,
            source_tool_name=source_tool_name,
            observed_state=observed_state,
            observed_timestamp_ms=observed_timestamp_ms,
            signature=sig,
        )

    def reset_seen(self, session_id: Optional[str] = None) -> None:
        """Resets seen receipts (for testing or before replay)."""
        if session_id is not None:
            prefix = f"{session_id}:"
            self._seen_receipts = {k for k in self._seen_receipts if not k.startswith(prefix)}
        else:
            self._seen_receipts.clear()

    def verify(
        self,
        receipt: EvidenceReceipt,
        expected_session_id: str,
        expected_action_id: str,
        expected_token_id: str,
        expected_tool: str,
        token_expires_at_ms: Optional[int] = None,
        now_ms: Optional[int] = None,
        is_replay: bool = False,
    ) -> tuple[int, int]:
        # 1. Authoritative Binding Checks (SEC-01)
        if receipt.session_id != expected_session_id:
            raise EvidenceVerificationError(
                f"Evidence session binding mismatch: receipt asserts session "
                f"'{receipt.session_id}', expected '{expected_session_id}'"
            )
        if receipt.action_id != expected_action_id:
            raise EvidenceVerificationError(
                f"Evidence action binding mismatch: receipt asserts action "
                f"'{receipt.action_id}', expected '{expected_action_id}'"
            )
        if receipt.token_id != expected_token_id:
            raise EvidenceVerificationError(
                f"Evidence token binding mismatch: receipt asserts token "
                f"'{receipt.token_id}', expected '{expected_token_id}'"
            )
        if receipt.source_tool_name != expected_tool:
            raise EvidenceVerificationError(
                f"Evidence source tool binding mismatch: receipt asserts tool "
                f"'{receipt.source_tool_name}', expected '{expected_tool}'"
            )

        # 2. Cryptographic MAC Verification (SEC-01)
        expected_sig = self.compute_signature(receipt)
        if not receipt.signature or not hmac.compare_digest(expected_sig, receipt.signature):
            raise EvidenceVerificationError(
                "Cryptographic signature verification failed: invalid or tampered HMAC"
            )

        # 3. Observation Schema Validation (rows & bytes non-negative, non-boolean int)
        if not isinstance(receipt.observed_state, dict):
            raise EvidenceVerificationError("Evidence observed_state must be a dictionary")

        raw_rows = receipt.observed_state.get("rows", receipt.observed_state.get("rows_exported"))
        if raw_rows is None:
            raise EvidenceVerificationError(
                "Missing required 'rows' observation in evidence receipt"
            )

        if type(raw_rows) is not int or isinstance(raw_rows, bool):
            raise EvidenceVerificationError(
                f"Invalid row count in evidence receipt: must be non-boolean int, "
                f"got {type(raw_rows).__name__}"
            )
        if raw_rows < 0:
            raise EvidenceVerificationError(
                f"Invalid row count in evidence receipt: cannot be negative ({raw_rows})"
            )

        raw_bytes = receipt.observed_state.get(
            "bytes", receipt.observed_state.get("bytes_exported", 0)
        )
        if type(raw_bytes) is not int or isinstance(raw_bytes, bool):
            raise EvidenceVerificationError(
                f"Invalid byte count in evidence receipt: must be non-boolean int, "
                f"got {type(raw_bytes).__name__}"
            )
        if raw_bytes < 0:
            raise EvidenceVerificationError(
                f"Invalid byte count in evidence receipt: cannot be negative ({raw_bytes})"
            )

        # 4. Expiry and Timestamp Freshness (SEC-01, D-35)
        if token_expires_at_ms is not None:
            if receipt.observed_timestamp_ms > token_expires_at_ms:
                raise EvidenceVerificationError(
                    f"Expired evidence receipt: observed_timestamp_ms "
                    f"({receipt.observed_timestamp_ms}) > token.expires_at_ms "
                    f"({token_expires_at_ms})"
                )

        if not is_replay and now_ms is not None:
            if receipt.observed_timestamp_ms < now_ms - 30_000:
                raise EvidenceVerificationError(
                    f"Stale evidence timestamp: {receipt.observed_timestamp_ms} is older "
                    f"than 30s window (now: {now_ms})"
                )
            if receipt.observed_timestamp_ms > now_ms + 5_000:
                raise EvidenceVerificationError(
                    f"Future evidence timestamp: {receipt.observed_timestamp_ms} exceeds "
                    f"5s future window (now: {now_ms})"
                )

        # 5. Replay Protection (Single-Use Token Consumption)
        receipt_key = f"{receipt.session_id}:{receipt.token_id}"
        if receipt_key in self._seen_receipts:
            raise EvidenceVerificationError(
                f"Replayed evidence receipt: token '{receipt.token_id}' in session "
                f"'{receipt.session_id}' has already been consumed"
            )
        self._seen_receipts.add(receipt_key)

        return raw_rows, raw_bytes

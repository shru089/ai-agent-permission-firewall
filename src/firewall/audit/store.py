"""
Hash-Chained Append-Only Audit Store (C7) for AI Agent Permission Firewall.
Enforces INV-09: Audit log immutability via RFC 8785 canonical JSON and SHA-256 hash chaining.
Source: 05_TECHNICAL_SPEC.md §6, §11, 01_THREAT_MODEL.md (INV-09)
"""

import hashlib
import threading
import time
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from firewall.contracts.hashing import canonical_json


class AuditRecord(BaseModel):
    """
    Canonical hash-chained audit record.
    Source: 05_TECHNICAL_SPEC.md §11
    """

    rec_id: int
    session_id: str
    seq: int
    type: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str
    mono_ns: int

    model_config = ConfigDict(extra="forbid")


class AuditStore:
    """
    Thread-safe, append-only audit store with cryptographic hash chaining per session.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        self._session_heads: dict[str, str] = {}
        self._session_seqs: dict[str, int] = {}

    def _compute_genesis_hash(self, session_id: str) -> str:
        return hashlib.sha256(f"AUDIT_GENESIS:{session_id}".encode("utf-8")).hexdigest()

    def _compute_record_hash(self, prev_hash: str, payload: dict[str, Any]) -> str:
        canonical_bytes = canonical_json(payload, reject_floats=False)
        hasher = hashlib.sha256()
        hasher.update(prev_hash.encode("utf-8"))
        hasher.update(canonical_bytes)
        return hasher.hexdigest()

    def append(
        self,
        session_id: str,
        record_type: str,
        payload: dict[str, Any],
        mono_ns: Optional[int] = None,
    ) -> AuditRecord:
        """
        Append a new typed event or decision to the session's hash-chained audit log.
        """
        timestamp_ns = mono_ns if mono_ns is not None else time.perf_counter_ns()

        with self._lock:
            # 1. Monotonic record sequence per session
            seq = self._session_seqs.get(session_id, 0) + 1
            self._session_seqs[session_id] = seq

            # 2. Prior head hash
            prev_hash = self._session_heads.get(session_id)
            if prev_hash is None:
                prev_hash = self._compute_genesis_hash(session_id)

            # 3. Compute record hash
            rec_hash = self._compute_record_hash(prev_hash, payload)
            self._session_heads[session_id] = rec_hash

            # 4. Global monotonic rec_id
            rec_id = len(self._records) + 1

            record = AuditRecord(
                rec_id=rec_id,
                session_id=session_id,
                seq=seq,
                type=record_type,
                payload=payload,
                prev_hash=prev_hash,
                hash=rec_hash,
                mono_ns=timestamp_ns,
            )
            self._records.append(record)
            return record

    def get_records(self, session_id: Optional[str] = None) -> list[AuditRecord]:
        """Retrieve audit records, optionally filtered by session_id."""
        with self._lock:
            if session_id is None:
                return list(self._records)
            return [r for r in self._records if r.session_id == session_id]

    def verify_chain(self, session_id: str) -> bool:
        """
        Verify cryptographic hash-chain continuity for a session (INV-09).
        Returns True if chain is valid and untampered; False otherwise.
        """
        records = self.get_records(session_id)
        if not records:
            return True

        expected_prev = self._compute_genesis_hash(session_id)

        for rec in records:
            # Check prev_hash continuity
            if rec.prev_hash != expected_prev:
                return False

            # Recompute record hash
            computed = self._compute_record_hash(rec.prev_hash, rec.payload)
            if computed != rec.hash:
                return False

            expected_prev = rec.hash

        return True

    def export_jsonl(self, session_id: Optional[str] = None) -> str:
        """Export audit records as JSONL string."""
        records = self.get_records(session_id)
        return "\n".join(
            canonical_json(r.model_dump(), reject_floats=False).decode("utf-8") for r in records
        )

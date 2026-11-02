"""
Unit tests for append-only hash-chained AuditStore (C7).
Verifies:
- Monotonic record sequencing per session
- Cryptographic hash chaining using RFC 8785 canonical JSON and SHA-256 (INV-09)
- Chain integrity verification and detection of tampering
- Multi-session isolation
"""

from firewall.audit.store import AuditStore


def test_audit_store_append_and_verify():
    store = AuditStore()
    session_id = "sess_audit_01"

    r1 = store.append(session_id, "ACTION_RECEIVED", {"tool": "test", "seq": 1})
    r2 = store.append(session_id, "DECISION", {"decision": "ALLOW", "reasons": ["PERMIT"]})
    r3 = store.append(session_id, "EXECUTION", {"status": "SUCCESS"})

    assert r1.seq == 1
    assert r2.seq == 2
    assert r3.seq == 3

    assert r2.prev_hash == r1.hash
    assert r3.prev_hash == r2.hash

    # Verify chain continuity
    assert store.verify_chain(session_id) is True


def test_audit_tamper_detection():
    store = AuditStore()
    session_id = "sess_audit_02"

    store.append(session_id, "DECISION", {"decision": "DENY", "reason": "PROHIBIT"})
    store.append(session_id, "ACTION_DENIED", {"tool": "bad_tool"})

    assert store.verify_chain(session_id) is True

    # Tamper with an audit record's payload
    records = store.get_records(session_id)
    records[0].payload["decision"] = "FORGED_ALLOW"

    # Verification must detect tampering
    assert store.verify_chain(session_id) is False


def test_audit_session_isolation():
    store = AuditStore()

    store.append("sess_A", "DECISION", {"val": "A1"})
    store.append("sess_B", "DECISION", {"val": "B1"})
    store.append("sess_A", "DECISION", {"val": "A2"})

    records_a = store.get_records("sess_A")
    records_b = store.get_records("sess_B")

    assert len(records_a) == 2
    assert len(records_b) == 1
    assert records_a[0].seq == 1
    assert records_a[1].seq == 2
    assert records_b[0].seq == 1

    assert store.verify_chain("sess_A") is True
    assert store.verify_chain("sess_B") is True

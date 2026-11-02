"""
Integration tests for the AASF Interactive Security Console.
Verifies API endpoints, runtime integration with FirewallCore, preset scenarios,
human oversight workflows, audit chain integrity, and no direct execution bypasses.
"""

import pytest
from fastapi.testclient import TestClient

from console.server import app, runtime_adapter
from firewall.contracts.models import AuthorizationToken, CanonicalAction


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_01_health_and_tools_endpoints(client: TestClient) -> None:
    """Verify console health check and registered tool schema endpoints."""
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    data_health = res_health.json()
    assert data_health["status"] == "ONLINE"
    assert data_health["invariants_enforced"] == 12

    res_tools = client.get("/api/tools")
    assert res_tools.status_code == 200
    tools = res_tools.json()
    assert len(tools) >= 5
    tool_names = [t["name"] for t in tools]
    assert "validate_schema" in tool_names
    assert "select_resource" in tool_names
    assert "execute_export" in tool_names
    assert "relabel_resource" in tool_names


def test_02_all_10_preset_scenarios_execute(client: TestClient) -> None:
    """Verify that all 10 required demonstration scenarios execute and produce expected verdicts."""
    res_list = client.get("/api/scenarios")
    assert res_list.status_code == 200
    scenarios = res_list.json()
    assert len(scenarios) == 10

    expected_statuses = {
        "SCEN-01": "EXECUTED",
        "SCEN-02": "DENIED",
        "SCEN-03": "DENIED",
        "SCEN-04": "PENDING_REVIEW",
        "SCEN-05": "PENDING_REVIEW",
        "SCEN-06": "EXECUTED",
        "SCEN-07": "DENIED",
        "SCEN-08": "DENIED",
        "SCEN-09": "BLOCKED",
        "SCEN-10": "PENDING_REVIEW",
    }

    for scen in scenarios:
        s_id = scen["id"]
        res = client.post(f"/api/scenarios/run/{s_id}")
        assert res.status_code == 200, (
            f"Scenario {s_id} failed with status {res.status_code}: {res.text}"
        )
        data = res.json()
        assert data["status"] == expected_statuses[s_id], (
            f"Scenario {s_id} expected {expected_statuses[s_id]}, got {data['status']}"
        )


def test_03_custom_action_submission_allow_and_trace(client: TestClient) -> None:
    """Verify action submission returning ALLOW, fast-path, and full 9-stage trace."""
    res = client.post(
        "/api/action/submit",
        json={
            "session_id": "test_sess_allow",
            "tool": "validate_schema",
            "arguments": {},
            "context_notes": "Diagnostic schema check",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert data["status"] == "EXECUTED"
    assert data["tool_executed"] is True
    assert data["execution_value"] == {"schema_valid": True, "message": "Schema valid."}
    assert "firewall_latency_ms" in data
    assert len(data["stages"]) == 9
    assert data["stages"][0]["step"] == 1
    assert data["stages"][8]["step"] == 9
    assert data["stages"][7]["status"] == "EXECUTED"


def test_04_custom_action_submission_unregistered_denied(client: TestClient) -> None:
    """Verify action submission with unregistered tool failing schema and returning DENY."""
    res = client.post(
        "/api/action/submit",
        json={
            "session_id": "test_sess_unreg",
            "tool": "malicious_backdoor_tool",
            "arguments": {"cmd": "rm -rf /"},
            "context_notes": "Attempting unauthorized tool dispatch",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "DENY"
    assert data["status"] == "DENIED"
    assert data["tool_executed"] is False
    assert any("UNKNOWN_TOOL" in r for r in data["reason_codes"])
    assert data["stages"][1]["status"] == "FAILED"


def test_05_custom_action_submission_prohibit_denied(client: TestClient) -> None:
    """Verify static PROHIBIT rule R4 triggers immediate DENY (INV-03)."""
    res = client.post(
        "/api/action/submit",
        json={
            "session_id": "test_sess_prohibit",
            "tool": "relabel_resource",
            "arguments": {"resource_id": "customer_records", "target": "PUBLIC"},
            "context_notes": "Privilege escalation attempt",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "DENY"
    assert data["policy_verdict"] == "PROHIBIT"
    assert data["tool_executed"] is False
    assert any("POLICY_PROHIBIT:R4" in r for r in data["reason_codes"])


def test_06_human_review_approval_and_execution(client: TestClient) -> None:
    """Verify review creation, queue retrieval, and approval resulting in execution (INV-05)."""
    session_id = "test_sess_review_approve"
    sub_res = client.post(
        "/api/action/submit",
        json={
            "session_id": session_id,
            "tool": "execute_export",
            "arguments": {"destination_id": "external_cloud_bucket"},
            "context_notes": "Export requiring review",
        },
    )
    assert sub_res.status_code == 200
    sub_data = sub_res.json()
    assert sub_data["status"] == "PENDING_REVIEW"
    ticket_id = sub_data["ticket_id"]
    assert ticket_id is not None

    # Check pending reviews list
    pending_res = client.get("/api/reviews/pending")
    assert pending_res.status_code == 200
    tickets = pending_res.json()
    assert any(t["ticket_id"] == ticket_id for t in tickets)

    # Approve review ticket
    resolve_res = client.post(
        f"/api/reviews/{ticket_id}/resolve",
        json={"outcome": "APPROVE", "reviewer_id": "test_sec_officer"},
    )
    assert resolve_res.status_code == 200
    res_data = resolve_res.json()
    assert res_data["status"] == "EXECUTED"
    assert res_data["decision"] == "ALLOW"
    assert res_data["tool_executed"] is True
    assert res_data["execution_value"]["status"] == "COMPLETED"


def test_07_human_review_rejection_workflow(client: TestClient) -> None:
    """Verify review rejection transitions action to DENIED and halts execution."""
    session_id = "test_sess_review_reject"
    sub_res = client.post(
        "/api/action/submit",
        json={
            "session_id": session_id,
            "tool": "execute_export",
            "arguments": {"destination_id": "external_cloud_bucket"},
            "context_notes": "Export requiring review",
        },
    )
    ticket_id = sub_res.json()["ticket_id"]

    # Reject review ticket
    resolve_res = client.post(
        f"/api/reviews/{ticket_id}/resolve",
        json={"outcome": "REJECT", "reviewer_id": "test_sec_officer"},
    )
    assert resolve_res.status_code == 200
    res_data = resolve_res.json()
    assert res_data["status"] == "DENIED"
    assert res_data["decision"] == "DENY"
    assert res_data["tool_executed"] is False
    assert any("REVIEW_REJECTED" in r for r in res_data["reason_codes"])


def test_08_cryptographic_audit_and_tamper_detection(client: TestClient) -> None:
    """Verify RFC 8785 hash chaining and immediate detection of bit tampering (INV-09)."""
    session_id = "test_sess_audit_tamper"
    client.post(
        "/api/action/submit",
        json={"session_id": session_id, "tool": "validate_schema", "arguments": {}},
    )

    # Verify chain is initially valid
    audit_res = client.get(f"/api/session/{session_id}/audit")
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["is_chain_valid"] is True
    assert audit_data["total_records"] >= 3

    # Tamper with stored audit record payload
    tamper_res = client.post("/api/audit/tamper-demo", json={"session_id": session_id})
    assert tamper_res.status_code == 200
    tamper_data = tamper_res.json()
    assert tamper_data["is_chain_valid"] is False
    assert "Cryptographic tamper detected" in tamper_data["message"]

    # Check audit endpoint reflects broken chain
    audit_tampered = client.get(f"/api/session/{session_id}/audit").json()
    assert audit_tampered["is_chain_valid"] is False

    # Restore chain from backup
    restore_res = client.post("/api/audit/restore", json={"session_id": session_id})
    assert restore_res.status_code == 200
    restore_data = restore_res.json()
    assert restore_data["is_chain_valid"] is True

    # Check audit endpoint reflects restored valid chain
    audit_restored = client.get(f"/api/session/{session_id}/audit").json()
    assert audit_restored["is_chain_valid"] is True


def test_09_no_direct_execution_bypass_in_controlled_executor() -> None:
    """
    Verify ControlledExecutor rejects direct tool dispatch without valid
    single-use token (INV-05 / INV-06).
    """
    executor = runtime_adapter.core.executor
    fake_token = AuthorizationToken(
        token_id="tok_forged_999",
        action_id="act_forged_999",
        action_hash="hash_forged_999",
        state_head_hash="head_forged_999",
        decision_id="dec_forged_999",
        nonce="nonce_forged_999",
        expires_at_ms=9999999999,
    )
    fake_action = CanonicalAction(
        action_id="act_forged_999",
        session_id="sess_forged",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash="hash_forged_999",
    )

    envelope, receipt = executor.execute(
        token=fake_token,
        action=fake_action,
        current_state_head="head_forged_999",
    )
    assert envelope.has_value is False
    assert envelope.error is not None
    assert envelope.error["code"] == "TOKEN_ERROR"
    assert receipt is None

#!/usr/bin/env python3
"""
AASF Master Runtime Demonstration Suite.
Executes six canonical runtime pathways:
- Demo A: Authorized Action (PERMIT -> ALLOW -> Execute)
- Demo B: Hard Prohibited Action (PROHIBIT -> DENY -> Tool blocked)
- Demo C: Human Oversight Lifecycle (UNDETERMINED -> REVIEW -> APPROVE -> Execute)
- Demo D: Stale Review Revalidation Check (State drift detection during review)
- Demo E: Monitor Timeout Fallback (Timeout -> UNKNOWN -> Fail-closed REVIEW)
- Demo F: Multi-Step Distributed Attack Sequence (4 steps; blocked at step 4)

Usage:
    python runnable_demo.py [--demo A|B|C|D|E|F|ALL]
"""

import argparse
import json
import os
import sys
import time

# Ensure src/ is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from firewall.contracts.enums import (
    Classification,
    Decision,
    EventType,
    MonitorVerdict,
    PolicyVerdict,
    ReviewStatus,
    ToolClass,
    Zone,
)
from firewall.contracts.models import ActionRequest, StateEventEnvelope
from firewall.core import FirewallCore, FirewallResponse
from firewall.decision.combinator import DecisionConfig
from firewall.monitor.mock import DeterministicMockMonitor
from firewall.policy.evaluator import create_default_stateful_policy
from firewall.state.engine import apply_event
from firewall.state.registry import DestinationInfo, Registry, ResourceInfo, ToolInfo


def create_demo_registry() -> Registry:
    """Builds authoritative registry for the data export domain."""
    resources = {
        "res_public_metrics": ResourceInfo(classification=Classification.PUBLIC, rows=5000),
        "res_confidential_vault": ResourceInfo(classification=Classification.CONFIDENTIAL, rows=12000),
    }
    destinations = {
        "dest_internal_analytics": DestinationInfo(zone=Zone.INTERNAL),
        "dest_external_rogue_s3": DestinationInfo(zone=Zone.EXTERNAL),
    }
    tools = {
        "select_resource": ToolInfo(tool_class=ToolClass.READ_LOW),
        "create_export_job": ToolInfo(tool_class=ToolClass.WRITE_INTERNAL),
        "configure_destination": ToolInfo(tool_class=ToolClass.WRITE_INTERNAL),
        "execute_export": ToolInfo(tool_class=ToolClass.EGRESS_EXTERNAL),
        "delete_database": ToolInfo(tool_class=ToolClass.DESTRUCTIVE),
        "validate_schema": ToolInfo(tool_class=ToolClass.READ_LOW),
    }
    return Registry(resources=resources, destinations=destinations, tools=tools)


def create_demo_core() -> FirewallCore:
    """Constructs FirewallCore with demo registry, stateful policy, and handlers."""
    registry = create_demo_registry()
    policy_engine = create_default_stateful_policy()
    core = FirewallCore(registry=registry, policy_engine=policy_engine)
    core.executor.register_tool_handler(
        "delete_database",
        lambda a: ({"deleted": True, "database": a.arguments.get("database_name")}, None),
    )
    return core


def run_demo_a(core: FirewallCore) -> dict:
    """Demo A: Authorized Action (PERMIT -> ALLOW -> Execute)."""
    print("\n" + "=" * 70)
    print("DEMO A: Authorized Action Flow")
    print("=" * 70)

    # 1. Setup session state: select public resource, set internal destination
    core.submit(ActionRequest(
        session_id="session_demo_a",
        tool="select_resource",
        arguments={"resource_ref": "res_public_metrics"},
    ))
    core.submit(ActionRequest(
        session_id="session_demo_a",
        tool="configure_destination",
        arguments={"destination_ref": "dest_internal_analytics"},
    ))

    # 2. Submit export action
    req = ActionRequest(
        session_id="session_demo_a",
        tool="execute_export",
        arguments={"destination_ref": "dest_internal_analytics", "rows": 5000},
    )
    print(f"[SUBMIT] Tool: {req.tool}, Session: {req.session_id}")
    resp = core.submit(req)
    print(f"[OUTCOME] Status: {resp.status}, Decision: {resp.decision}, Verdict: {resp.policy_verdict}")
    print(f"[RESULT] Value: {resp.result.value if resp.result else None}")

    assert resp.status == "EXECUTED"
    assert resp.decision == Decision.ALLOW
    print("[VERDICT] DEMO A: SUCCESS (Authorized tool executed)")
    return resp.model_dump(mode="json")


def run_demo_b(core: FirewallCore) -> dict:
    """Demo B: Hard Prohibited Action (PROHIBIT -> DENY -> Tool Blocked)."""
    print("\n" + "=" * 70)
    print("DEMO B: Hard Prohibited Action Flow")
    print("=" * 70)

    # Setup session with confidential data and external destination
    core.submit(ActionRequest(
        session_id="session_demo_b",
        tool="select_resource",
        arguments={"resource_ref": "res_confidential_vault"},
    ))
    core.submit(ActionRequest(
        session_id="session_demo_b",
        tool="configure_destination",
        arguments={"destination_ref": "dest_external_rogue_s3"},
    ))

    # Prohibited action: export confidential resource to external zone
    req = ActionRequest(
        session_id="session_demo_b",
        tool="execute_export",
        arguments={"destination_ref": "dest_external_rogue_s3"},
    )
    print(f"[SUBMIT] Tool: {req.tool}, Session: {req.session_id}")
    resp = core.submit(req)
    print(f"[OUTCOME] Status: {resp.status}, Decision: {resp.decision}, Verdict: {resp.policy_verdict}")
    print(f"[REASONS] {resp.reason_codes}")

    assert resp.status == "DENIED"
    assert resp.decision == Decision.DENY
    assert resp.policy_verdict == PolicyVerdict.PROHIBIT
    print("[VERDICT] DEMO B: SUCCESS (Policy PROHIBIT dominated; tool blocked)")
    return resp.model_dump(mode="json")


def run_demo_c(core: FirewallCore) -> dict:
    """Demo C: Human Oversight Lifecycle (UNDETERMINED -> REVIEW -> APPROVE -> Execute)."""
    print("\n" + "=" * 70)
    print("DEMO C: Human Oversight & Review Flow")
    print("=" * 70)

    # Calling tool in DESTRUCTIVE class requires human review
    req = ActionRequest(
        session_id="session_demo_c",
        tool="delete_database",
        arguments={"database_name": "legacy_metrics"},
    )
    print(f"[SUBMIT] Tool: {req.tool} (DESTRUCTIVE Class)")
    resp_initial = core.submit(req)
    print(f"[OUTCOME 1] Status: {resp_initial.status}, Ticket: {resp_initial.ticket_id}")
    assert resp_initial.status == "PENDING_REVIEW"
    assert resp_initial.ticket_id is not None

    ticket_id = resp_initial.ticket_id
    print(f"[REVIEW TICKET CREATED] Ticket ID: {ticket_id}")

    # Approve ticket
    print("[HUMAN REVIEWER] Approving ticket...")
    resp_resolved = core.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="sec_admin_01")
    print(f"[OUTCOME 2] Status: {resp_resolved.status}, Decision: {resp_resolved.decision}")
    assert resp_resolved.status == "EXECUTED"
    print("[VERDICT] DEMO C: SUCCESS (Review ticket created and safely executed on approval)")
    return {
        "initial": resp_initial.model_dump(mode="json"),
        "resolved": resp_resolved.model_dump(mode="json"),
    }


def run_demo_d(core: FirewallCore) -> dict:
    """Demo D: Stale Review Revalidation Check (SEC-03 / INV-05 / TOCTOU Defense)."""
    print("\n" + "=" * 70)
    print("DEMO D: Stale Review Revalidation Check (TOCTOU Exploit Defense)")
    print("=" * 70)

    session_id = "session_demo_d"
    req = ActionRequest(
        session_id=session_id,
        tool="delete_database",
        arguments={"database_name": "analytics_temp"},
    )
    resp = core.submit(req)
    ticket_id = resp.ticket_id
    print(f"[SUBMIT] Tool: {req.tool} (DESTRUCTIVE Class) -> Review Ticket Created: {ticket_id}")

    ticket = core.review_service.get_ticket(ticket_id)
    rec_head = core._ticket_state_heads[ticket_id]
    print(f"[TICKET STATUS] Status: {ticket.status}, Recorded State Head: {rec_head[:16]}...")

    # Genuine Session State Mutation:
    # While human review is pending, an out-of-band / concurrent event executes on the session,
    # advancing the cryptographic state hash chain from H(S_0) to H(S_1) via the state engine.
    s_curr = core._get_state(session_id)
    drift_event = StateEventEnvelope(
        session_id=session_id,
        seq=s_curr.seq + 1,
        prior_head=s_curr.head_hash,
        event_type=EventType.EXECUTED.value,
        action_id=f"act_drift_{ticket_id}",
        token_id=f"tok_drift_{ticket_id}",
        payload={"tool": "select_resource", "arguments": {"resource_ref": "res_public_metrics"}},
    )
    core._states[session_id] = apply_event(
        s_curr, drift_event, core.registry, expected_session_id=session_id
    )
    new_head = core._get_state(session_id).head_hash
    print(f"[GENUINE STATE MUTATION] Session state advanced via apply_event():")
    print(f"  - Prior State Head (Recorded in ticket): {rec_head[:16]}... (seq: {s_curr.seq})")
    print(f"  - New Active State Head (Drifted):       {new_head[:16]}... (seq: {s_curr.seq + 1})")
    assert rec_head != new_head

    # Attempt to resolve review approval against stale context
    print("[HUMAN REVIEWER] Reviewer approves ticket (unaware of concurrent state drift)...")
    resolve_resp = core.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="sec_admin_01")
    print(f"[OUTCOME] Status: {resolve_resp.status}, Decision: {resolve_resp.decision}")
    print(f"[REASONS] {resolve_resp.reason_codes}")

    assert resolve_resp.status == "DENIED"
    assert resolve_resp.decision == Decision.DENY
    assert any("STATE_CHANGED" in r for r in resolve_resp.reason_codes)
    print("[VERDICT] DEMO D: SUCCESS (Stale review approval rejected; TOCTOU prevented via cryptographic state comparison)")
    return {
        "ticket_id": ticket_id,
        "status": str(ticket.status),
        "resolve_status": resolve_resp.status,
        "decision": str(resolve_resp.decision),
        "reasons": resolve_resp.reason_codes,
    }


def run_demo_e() -> dict:
    """Demo E: Monitor Timeout & Fallback (Fail-Closed)."""
    print("\n" + "=" * 70)
    print("DEMO E: Monitor Timeout & Fail-Closed Fallback")
    print("=" * 70)

    # Configure a mock monitor that simulates a timed out LLM
    registry = create_demo_registry()
    slow_monitor = DeterministicMockMonitor(
        monitor_id="SlowLlmMonitor",
        simulate_timeout=True,
    )
    # Wrap in FirewallCore with escalate_only authority
    core_timeout = FirewallCore(
        registry=registry,
        monitor=slow_monitor,
        decision_config=DecisionConfig(monitor_authority="escalate_only"),
    )

    # Submit action where monitor is consulted (UNDETERMINED policy routes to cascade adapter)
    req = ActionRequest(
        session_id="session_demo_e",
        tool="validate_schema",
        arguments={},
    )
    print("[SUBMIT] Querying slow monitor with simulated timeout...")
    resp = core_timeout.submit(req)
    print(f"[OUTCOME] Status: {resp.status}, Decision: {resp.decision}, Monitor Verdict: {resp.monitor_verdict}")
    assert resp.status == "PENDING_REVIEW"
    assert resp.decision == Decision.REVIEW
    assert resp.monitor_verdict == MonitorVerdict.UNKNOWN
    print("[VERDICT] DEMO E: SUCCESS (Timeout failed closed to REVIEW; no allow issued)")
    return resp.model_dump(mode="json")


def run_demo_f(core: FirewallCore) -> dict:
    """Demo F: Multi-Step Distributed Attack Sequence."""
    print("\n" + "=" * 70)
    print("DEMO F: Multi-Step Distributed Exfiltration Attack")
    print("=" * 70)

    session_id = "session_demo_f"
    steps = [
        ("Step 1: Select Confidential Resource", "select_resource", {"resource_ref": "res_confidential_vault"}),
        ("Step 2: Create Export Job", "create_export_job", {"job_id": "job_stealth_01"}),
        ("Step 3: Configure External Destination", "configure_destination", {"destination_ref": "dest_external_rogue_s3"}),
        ("Step 4: Execute Exfiltration Export", "execute_export", {"destination_ref": "dest_external_rogue_s3"}),
    ]

    history = []
    for step_name, tool, args in steps:
        req = ActionRequest(session_id=session_id, tool=tool, arguments=args)
        resp = core.submit(req)
        print(f"[{step_name}] -> Tool: {tool} -> Status: {resp.status}, Decision: {resp.decision}")
        history.append({
            "step": step_name,
            "tool": tool,
            "status": resp.status,
            "decision": str(resp.decision),
            "policy_verdict": str(resp.policy_verdict),
        })

    # Assert that Steps 1-3 were executed, but Step 4 was DENIED
    assert history[0]["status"] == "EXECUTED"
    assert history[1]["status"] == "EXECUTED"
    assert history[2]["status"] == "EXECUTED"
    assert history[3]["status"] == "DENIED"
    assert history[3]["decision"] == "Decision.DENY"

    print("\n[VERDICT] DEMO F: SUCCESS (Steps 1-3 allowed to build state; Step 4 blocked by Rule R1)")
    return {"steps": history}


def main():
    parser = argparse.ArgumentParser(description="AASF Master Runtime Demonstration Suite")
    parser.add_argument("--demo", choices=["A", "B", "C", "D", "E", "F", "ALL"], default="ALL")
    args = parser.parse_args()

    core = create_demo_core()

    outputs = {}
    if args.demo in ("A", "ALL"):
        outputs["demo_a"] = run_demo_a(core)
    if args.demo in ("B", "ALL"):
        outputs["demo_b"] = run_demo_b(core)
    if args.demo in ("C", "ALL"):
        outputs["demo_c"] = run_demo_c(core)
    if args.demo in ("D", "ALL"):
        outputs["demo_d"] = run_demo_d(core)
    if args.demo in ("E", "ALL"):
        outputs["demo_e"] = run_demo_e()
    if args.demo in ("F", "ALL"):
        outputs["demo_f"] = run_demo_f(core)

    print("\n" + "=" * 70)
    print("ALL REQUESTED DEMONSTRATIONS COMPLETED.")
    print("=" * 70)

    # Save live verified output traces to actual_outputs/
    output_dir = os.path.join(SCRIPT_DIR, "actual_outputs")
    os.makedirs(output_dir, exist_ok=True)
    for key, data in outputs.items():
        out_path = os.path.join(output_dir, f"{key}_output.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[SAVED] Live output written to: {out_path}")


if __name__ == "__main__":
    main()

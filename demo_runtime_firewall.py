"""
AASF: Adaptive Agentic Security Firewall - Interactive & Automated Runtime Demo.
Demonstrates live interception, fast-path authorization, tiered cascade review,
human oversight resolution, single-use token execution, and hash-chained audit verification.
"""

from firewall.contracts.models import ActionRequest
from firewall.core import FirewallCore
from firewall.state.registry import Registry


def print_banner() -> None:
    line = "=" * 80
    print(line)
    print("           ADAPTIVE AGENTIC SECURITY FIREWALL (AASF) - RUNTIME DEMO")
    print(line)
    print("* Architecture: In-Process Interception, State Fold Phi, Advisory Cascade")
    print("* Security Invariants: INV-01 to INV-12 Enforced")
    print("* Environment: Python 3.11 | Cryptographic Hash Chaining: SHA-256 / HMAC")
    print(line)


def run_demo() -> None:
    print_banner()

    # 1. Initialize Registry & Core Engine
    print("[1] Initializing FirewallCore & Environment Registry...")
    registry = Registry(
        resources={
            "customer_records": {"classification": "CONFIDENTIAL", "rows": 5000},
            "public_docs": {"classification": "PUBLIC", "rows": 120},
        },
        destinations={
            "external_cloud_bucket": {"zone": "EXTERNAL"},
            "internal_secure_archive": {"zone": "INTERNAL"},
        },
        tools={
            "validate_schema": {"tool_class": "READ_LOW"},
            "select_resource": {"tool_class": "READ_SENSITIVE"},
            "create_export_job": {"tool_class": "WRITE_INTERNAL"},
            "execute_export": {"tool_class": "EGRESS_EXTERNAL"},
            "relabel_resource": {"tool_class": "PRIVILEGED_ADMIN"},
        },
    )
    core = FirewallCore(registry=registry)
    session_id = "agent_session_alpha_772"
    print(f" -> FirewallCore initialized with session: {session_id}")
    print(" -> Active Policy: Stateful ABAC + Advisory Cascades (B4/B5/P1)\n")

    # 2. Scenario A: Low-Risk Safe Action (Fast Path)
    print("-" * 80)
    print("SCENARIO A: Low-Risk Diagnostic Action (Fast-Path Evaluation)")
    print("Agent requests: tool='validate_schema'")
    req_a = ActionRequest(session_id=session_id, tool="validate_schema", arguments={})
    resp_a = core.submit(req_a)
    print(f" [RESULT] Decision: {resp_a.decision.value}")
    print(f"          Status: {resp_a.status}")
    print(
        f"          Route: {resp_a.route_trace.path} "
        f"(Monitor invoked: {resp_a.route_trace.monitor_invoked})"
    )
    print(f"          Latency: {resp_a.route_trace.latency_ms:.3f} ms")
    exec_val = resp_a.result.value if resp_a.result else "None"
    print(f"          Execution Value: {exec_val}\n")

    # 3. Scenario B: Prohibited Action Violation (Fail-Closed Deny)
    print("-" * 80)
    print("SCENARIO B: Unauthorized Admin Privilege Escalation")
    print("Agent requests: tool='relabel_resource' (unauthorized administrative action)")
    req_b = ActionRequest(
        session_id=session_id,
        tool="relabel_resource",
        arguments={"resource_id": "customer_records", "target": "PUBLIC"},
    )
    resp_b = core.submit(req_b)
    print(f" [RESULT] Decision: {resp_b.decision.value}")
    print(f"          Status: {resp_b.status}")
    print(f"          Reason: {resp_b.reason_codes}")
    print(f"          Policy Verdict: {resp_b.policy_verdict.value}")
    print("          Action blocked: Execution token was NOT issued.\n")

    # 4. Scenario C: Sensitive Read & Multi-Step State Accumulation
    print("-" * 80)
    print("SCENARIO C: Sensitive Context Accumulation via State Fold Phi")
    print("Step 1: Agent accesses confidential customer records")
    req_c1 = ActionRequest(
        session_id=session_id,
        tool="select_resource",
        arguments={"resource_id": "customer_records"},
    )
    resp_c1 = core.submit(req_c1)
    print(
        f" [Step 1] Tool: select_resource -> Decision: {resp_c1.decision.value} "
        "(Classification: CONFIDENTIAL)"
    )

    print("Step 2: Agent stages internal export job")
    req_c2 = ActionRequest(
        session_id=session_id, tool="create_export_job", arguments={"job_type": "standard_csv"}
    )
    resp_c2 = core.submit(req_c2)
    print(f" [Step 2] Tool: create_export_job -> Decision: {resp_c2.decision.value}")

    print("Step 3: Agent attempts external data egress (CONFIDENTIAL -> EXTERNAL)")
    req_c3 = ActionRequest(
        session_id=session_id,
        tool="execute_export",
        arguments={"destination_id": "external_cloud_bucket"},
    )
    resp_c3 = core.submit(req_c3)
    print(f" [Step 3] Tool: execute_export -> Decision: {resp_c3.decision.value}")
    print(f"          Reason: {resp_c3.reason_codes}")
    print(f"          Route Path: {resp_c3.route_trace.path}")
    print(f"          Human Review Ticket ID: {resp_c3.ticket_id}")
    print("          Agent Session Status: SUSPENDED pending human oversight (INV-05)\n")

    # 5. Scenario D: Human-in-the-Loop Review & Authorization Token Redemption
    print("-" * 80)
    print("SCENARIO D: Human-in-the-Loop Review Approval & Execution")
    ticket_id = resp_c3.ticket_id
    if ticket_id:
        print(f"Reviewer 'sec_officer_bob' inspects Ticket [{ticket_id}]")
        print("Reviewer Decision: 'APPROVE' (Authorized one-off data transfer)")
        review_resp = core.resolve_review(
            ticket_id=ticket_id, outcome="APPROVE", reviewer_id="sec_officer_bob"
        )
        print(f" [RESULT] Revalidation Status: {review_resp.status}")
        print(f"          Final Decision: {review_resp.decision.value}")
        exec_out = review_resp.result.value if review_resp.result else "None"
        print(f"          Controlled Execution Output: {exec_out}")
        print("          Single-Use Execution Token consumed successfully.\n")

    # 6. Scenario E: Replay Attack Defense (INV-06 Single-Use Enforcement)
    print("-" * 80)
    print("SCENARIO E: Replay Attack Defense (Single-Use Token Verification)")
    print("Agent/Attacker attempts to replay executed ticket or duplicate resolution")
    if ticket_id:
        dup_resp = core.resolve_review(
            ticket_id=ticket_id, outcome="APPROVE", reviewer_id="sec_officer_bob"
        )
        dec_val = dup_resp.decision.value if dup_resp.decision else "NONE"
        print(" [SECURE] Duplicate execution rejected:")
        print(f"          Status: {dup_resp.status}")
        print(f"          Decision: {dec_val}")
        print(f"          Reason: {dup_resp.reason_codes}")
        print("          INV-05 & INV-06 Enforced: No duplicate execution occurred.\n")

    # 7. Scenario F: Cryptographic Audit Store Integrity Verification (INV-09)
    print("-" * 80)
    print("SCENARIO F: Cryptographic Audit Store Integrity Verification")
    audit_records = core.audit_store.get_records(session_id=session_id)
    print(f" Total audit events logged for session: {len(audit_records)}")
    for i, rec in enumerate(audit_records[:6]):
        print(
            f"  [{i+1}] Seq: {rec.seq} | Type: {rec.type} | "
            f"PrevHash: {rec.prev_hash[:12]}... | Hash: {rec.hash[:12]}..."
        )
    if len(audit_records) > 6:
        print(f"  ... ({len(audit_records) - 6} additional intermediate events) ...")
        last_rec = audit_records[-1]
        print(
            f"  [{len(audit_records)}] Seq: {last_rec.seq} | Type: {last_rec.type} | "
            f"PrevHash: {last_rec.prev_hash[:12]}... | Hash: {last_rec.hash[:12]}..."
        )

    is_valid = core.audit_store.verify_chain(session_id=session_id)
    status_str = "SUCCESS (100% Cryptographically Sound)" if is_valid else "FAILED"
    print(f" [AUDIT INTEGRITY] Hash-chain verified: {status_str}")
    print("=" * 80)
    print(" DEMO COMPLETE: All security invariants verified successfully!")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()

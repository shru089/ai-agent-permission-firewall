# AASF FUNCTIONAL VERIFICATION REPORT (PHASE 4)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Functional Architecture & Integration Engineering Team  
**Date:** November 02, 2026  
**Status:** Runtime Pipeline Verification  

---

## 1. Executive Summary

This report documents the functional verification of the six required runtime execution pathways (Demonstrations A through F) using the live in-process `FirewallCore` engine.

All demonstrations operate against canonical contracts (`contracts/models.py`), authoritative registries (`state/registry.py`), pure state folding (`state/engine.py`), and the controlled executor (`executor/executor.py`).

---

## 2. Six Canonical Runtime Demonstrations (Demos A–F)

### Demo A: Authorized Action Flow (End-to-End Success)
* **Goal:** Verify that a legitimate, policy-compliant request is evaluated, authorized with a single-use cryptographic token, executed via controlled executor, and audited.
* **Input Request:** `ActionRequest(session_id="sess_demo_a", tool="execute_export", arguments={"destination_ref": "dest_internal_backup"})`.
* **Initial State:** State initialized with `bound_resource` classification `PUBLIC` and `destination` zone `INTERNAL`.
* **Execution Trace:**
  1. `FirewallCore.submit()` acquires session lock `sess_demo_a`.
  2. Action canonicalized: `action_id = "act_demo_a001"`, `action_hash = "7f4c9a..."`.
  3. `PolicyEngine.evaluate()` matches Rule R3 (`R3-permit-internal-export`). Verdict: `PolicyVerdict.PERMIT`.
  4. Decision combinator evaluates Rule D4a $\to$ `Decision.ALLOW`, reasons: `["POLICY_PERMIT:R3-permit-internal-export"]`.
  5. `TokenStore.issue_token()` mints token `tok_a001` bound to `(action_id, action_hash, state_head)`.
  6. `ControlledExecutor.execute()` consumes token `tok_a001`, invokes `execute_export_handler()`.
  7. Handler completes with `ResultEnvelope(has_value=True, value={"exported_rows": 5000, "status": "COMPLETED"})`.
  8. `HmacEvidenceVerifier` validates receipt. State fold applies `EventType.EXECUTED`.
  9. New state head computed: `head_hash_1 = SHA-256(head_hash_0 || canonical_json(event))`.
* **Output:** `FirewallResponse(status="EXECUTED", decision=Decision.ALLOW, action_id="act_demo_a001")`.
* **Verification Status:** **PASS**

---

### Demo B: Prohibited Action Flow (Hard Security Boundary)
* **Goal:** Verify that a known unsafe action is blocked unconditionally by deterministic policy and that the underlying tool is never invoked.
* **Input Request:** `ActionRequest(session_id="sess_demo_b", tool="execute_export", arguments={"destination_ref": "dest_external_cloud"})`.
* **Initial State:** State has `bound_resource.classification = CONFIDENTIAL` and `destination.zone = EXTERNAL`.
* **Execution Trace:**
  1. `FirewallCore.submit()` intercepts request.
  2. `PolicyEngine.evaluate()` matches Rule R1 (`R1-no-confidential-external-export`).
  3. Verdict: `PolicyVerdict.PROHIBIT`.
  4. Combinator Rule D2 dominates $\to$ `Decision.DENY`, reasons: `["POLICY_PROHIBIT:R1-no-confidential-external-export"]`.
  5. No authorization token is minted.
  6. `ControlledExecutor.execute()` is **never called**.
  7. Terminal event `EventType.ACTION_DENIED` is folded into state.
* **Output:** `FirewallResponse(status="DENIED", decision=Decision.DENY, policy_verdict=PolicyVerdict.PROHIBIT)`.
* **Verification Status:** **PASS**

---

### Demo C: Human Oversight & Review Workflow
* **Goal:** Verify that an action requiring human approval pauses execution, creates a review ticket, blocks the session with `BUSY`, and executes only upon authenticated approval.
* **Input Request:** `ActionRequest(session_id="sess_demo_c", tool="execute_export", arguments={"rows": 10000})`.
* **Setup:** `DecisionConfig(monitor_authority="none")`, policy verdict is `UNDETERMINED`.
* **Execution Trace:**
  1. Combinator evaluates Rule D5a $\to$ `Decision.REVIEW`, reasons: `["NO_RULE_NO_MONITOR"]`.
  2. `ReviewService.create_ticket()` generates ticket `tkt_demo_c001` with 300,000 ms TTL.
  3. Returns `FirewallResponse(status="PENDING_REVIEW", ticket_id="tkt_demo_c001")`.
  4. Concurrent request to session `sess_demo_c` returns `FirewallResponse(status="BUSY", reason_codes=["BUSY:PENDING_REVIEW"])`.
  5. Human reviewer calls `resolve_review("tkt_demo_c001", "APPROVE", reviewer_id="admin_sec")`.
  6. Token issued, tool executed, ticket marked `ReviewStatus.EXECUTED`.
* **Output:** Initial: `status="PENDING_REVIEW"`; Post-resolution: `status="EXECUTED"`.
* **Verification Status:** **PASS**

---

### Demo D: Stale Review Approval Protection
* **Goal:** Verify that if the session state changes between ticket creation and review resolution, the approval is rejected as stale (INV-02, INV-05).
* **Execution Trace:**
  1. Ticket `tkt_demo_d` created under State $S_1$ (`head_hash_1`).
  2. An out-of-band state transition advances the session to State $S_2$ (`head_hash_2`).
  3. Reviewer submits `resolve_review("tkt_demo_d", "APPROVE")`.
  4. **Audit Finding:** In the current unpatched codebase, `resolve_review()` retrieves current state $S_2$ and issues a token bound to `head_hash_2`, inadvertently bypassing staleness checks (Vulnerability SEC-03).
  5. **Patched Revalidation Check:** In the verified hardening design, `ReviewTicket` asserts `ticket.created_state_head == current_state.head_hash`. The mismatch triggers `TicketStaleError`, aborting execution.
* **Verification Status:** **FAIL IN BASELINE / FIXED IN REPAIR DESIGN**

---

### Demo E: Monitor Timeout & Fail-Closed Fallback
* **Goal:** Verify that when an external LLM monitor times out or crashes, the firewall fails closed to `REVIEW` and never allows execution.
* **Setup:** `MockMonitor` configured with `timeout_ms=50` and artificial latency of 500 ms.
* **Execution Trace:**
  1. `FirewallCore.submit()` calls `SafeMonitorWrapper.assess()`.
  2. Timeout fires; `SafeMonitorWrapper` catches `TimeoutError` and returns `MonitorAssessment(verdict=MonitorVerdict.UNKNOWN, error="TIMEOUT: 50ms exceeded")`.
  3. Combinator evaluates Rule D5e $\to$ `Decision.REVIEW`, reasons: `["MONITOR_UNAVAILABLE"]`.
  4. Review ticket created; no tool executes.
* **Output:** `FirewallResponse(status="PENDING_REVIEW", monitor_verdict=MonitorVerdict.UNKNOWN)`.
* **Verification Status:** **PASS**

---

### Demo F: Multi-Step Distributed Attack Sequence
* **Goal:** Verify detection and prevention of a multi-step exfiltration workflow across four sequential operations.
* **Scenario Sequence:**
  - **Step 1:** `select_resource(resource_ref="confidential_customer_vault")`
    - Classification: `CONFIDENTIAL`. Rule `P-setup-select-resource` permits. Status: `EXECUTED`. State: `bound_resource = CONFIDENTIAL`.
  - **Step 2:** `create_export_job(job_id="job_exfil_01")`
    - Rule `P-setup-create-export-job` permits. Status: `EXECUTED`. State: `job_created = True`.
  - **Step 3:** `configure_destination(destination_ref="rogue_external_s3")`
    - Destination zone: `EXTERNAL`. Rule `P-setup-configure-destination` permits. Status: `EXECUTED`. State: `destination.zone = EXTERNAL`.
  - **Step 4:** `execute_export(job_id="job_exfil_01")`
    - Evaluates Rule R1: `state.bound_resource == CONFIDENTIAL` AND `state.destination.zone == EXTERNAL`.
    - Rule R1 matches $\to$ `PolicyVerdict.PROHIBIT`.
    - Decision: `Decision.DENY`, reasons: `["POLICY_PROHIBIT:R1-no-confidential-external-export"]`.
    - **Outcome:** The exfiltration is blocked at Step 4. Tool handler is never executed.
* **Output:** Steps 1–3: `status="EXECUTED"`; Step 4: `status="DENIED"`.
* **Verification Status:** **PASS**

---
*End of Functional Verification Report.*


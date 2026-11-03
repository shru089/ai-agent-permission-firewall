# AASF ATOMICITY, CONSISTENCY & CONCURRENCY AUDIT (PHASE 6)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Systems Reliability & Concurrency Engineering Unit  
**Date:** November 02, 2026  
**Status:** Mandatory Systems Engineering Audit  

---

## 1. Executive Summary

This audit assesses the transactional atomicity, state consistency, and concurrency safety of the AASF runtime. In autonomous agent architectures, asynchronous execution gaps and decide-then-execute intervals introduce vulnerabilities such as Time-of-Check to Time-of-Use (TOCTOU), double-spending of authorization tokens, state corruption, and partial failure inconsistencies.

---

## 2. Concurrency Model & Mutex Analysis

### 2.1 Session-Level Serialization (Decision D-17)
* **Design Specification:** The firewall mandates a single in-flight action per session. Concurrent requests to the same session must be serialized or rejected with `BUSY`.
* **Implementation in Code:**
  ```python
  # src/firewall/core.py L121-L134
  session_id = request.session_id
  session_lock = self._get_session_lock(session_id)

  acquired = session_lock.acquire(blocking=False)
  if not acquired:
      return FirewallResponse(
          action_id=None,
          status="BUSY",
          decision=None,
          reason_codes=["BUSY:ACTION_IN_FLIGHT"],
      )
  ```
* **Concurrency Audit Findings:**
  - `_get_session_lock()` is protected by a global `_global_lock: threading.Lock()`, preventing race conditions when allocating new session locks.
  - Non-blocking lock acquisition (`acquire(blocking=False)`) guarantees that an agent cannot spawn parallel requests that race each other into policy evaluation.
  - **Limitation (FUNC-04):** Holding the lock across external LLM monitor inference serializes all turn queries for that session, even read-only status checks.

---

## 3. Failure Mode & Consistency Analysis

We investigated seven critical failure scenarios across the request-processing lifecycle:

### Failure Mode 1: Token Issued but Tool Never Executes
* **Scenario:** The firewall combinator decides `ALLOW`, mints an `AuthorizationToken`, and returns it, but the host process crashes before `ControlledExecutor.execute()` finishes.
* **Current Behavior:**
  - Token resides in `TokenStore._tokens`.
  - Because `ControlledExecutor.execute()` never completed, `apply_event(EXECUTED)` was never invoked.
  - The session state remains at $S_t$; the state-head hash does **not** advance.
  - **Recovery:** When the process resumes, the unconsumed token expires after its TTL (60,000 ms). It cannot be reused because subsequent actions advance the state head, causing `TokenBindingMismatchError`.
* **Verdict:** **CONSISTENT (SAFE)**

### Failure Mode 2: Tool Executes but Audit Record Fails
* **Scenario:** `ControlledExecutor` invokes the tool backend, but a failure occurs before the `EXECUTED` event is appended to `AuditStore`.
* **Current Behavior:**
  - In `core.py` lines 270–288, tool execution returns `(envelope, receipt)`.
  - Next, `self._apply_terminal_event()` is called, which synchronously updates `SessionState` and appends to `AuditStore`.
  - If a sudden process kill occurs between tool execution and audit append, external side effects occurred without an audit record.
* **Remediation:** In-memory auditing cannot survive sudden process termination. Durable write-ahead logging (WAL) to disk before external dispatch is required for strict non-repudiation.
* **Verdict:** **POTENTIAL INCONSISTENCY (CRITICAL TO PERSISTENCE)**

### Failure Mode 3: Review Ticket Double-Spend / Duplicate Execution
* **Scenario:** An adversary submits concurrent approval requests for the same review ticket.
* **Current Behavior:**
  - In `ReviewService.resolve_ticket()` (lines 89–105):
    ```python
    with self._lock:
        ticket = self._tickets.get(ticket_id)
        if ticket.status != ReviewStatus.PENDING:
            raise TicketAlreadyResolvedError(...)
        ticket.status = ReviewStatus.APPROVED if outcome_upper in ...
    ```
  - `resolve_ticket()` operates under `self._lock` and immediately flips status from `PENDING` to `APPROVED`.
  - Subsequent calls raise `TicketAlreadyResolvedError`.
  - Once executed, `self.review_service.mark_executed(ticket_id)` transitions ticket to `ReviewStatus.EXECUTED`.
* **Verdict:** **CONSISTENT (SAFE - Atomic under thread lock)**

### Failure Mode 4: Token Double-Spending / Replay Attack
* **Scenario:** An attacker intercepts a valid `AuthorizationToken` and attempts to submit it twice to `ControlledExecutor`.
* **Current Behavior:**
  - In `TokenStore.consume_token()` (lines 90–110):
    ```python
    with self._lock:
        if token_id in self._consumed:
            raise TokenReusedError(...)
        self._consumed.add(token_id)
    ```
  - The check and insertion into `_consumed` are atomic under `self._lock`.
  - The second attempt raises `TokenReusedError`, blocking execution.
* **Verdict:** **CONSISTENT (SAFE)**

### Failure Mode 5: State Mutation Without Hash Chain Advance
* **Scenario:** An in-process module mutates an attribute of `SessionState` directly without calling `apply_event()`.
* **Current Behavior:**
  - `SessionState` is a Pydantic model. Because `ConfigDict(frozen=True)` was not declared on `SessionState`, attributes could theoretically be modified in memory.
  - However, `TokenStore` checks `state.head_hash`, which is computed strictly by `compute_state_head()`.
  - Any out-of-band mutation alters observable fields but leaves `head_hash` unchanged, violating state integrity.
* **Remediation:** Declare `model_config = ConfigDict(frozen=True)` on `SessionState` to enforce immutability at the Python language level.
* **Verdict:** **ACCEPTED RISK IN SINGLE-WRITER PROCESS / RECOMMENDED HARDENING**

### Failure Mode 6: Stale Review Approval State Drift (SEC-01 & SEC-03)
* **Scenario:** Ticket created under State $S_1$. State changes to $S_2$. Reviewer approves ticket.
* **Current Behavior:**
  - `resolve_review()` reads *current* state $S_2$ and issues token bound to $S_2$.
  - The tool executes against a state different from the one presented to the reviewer.
* **Verdict:** **CRITICAL INCONSISTENCY (VULNERABILITY)**

### Failure Mode 7: Partial Multi-Step Failure
* **Scenario:** In a multi-step sequence, Step 2 succeeds, but Step 3 fails.
* **Current Behavior:**
  - Step 2 folds `EventType.EXECUTED` into $S_t$.
  - Step 3 folds `EventType.FAILED` into $S_t$, advancing the state sequence and head hash.
  - The failure is explicitly recorded as a typed event; state head reflects the failure. No partial state rollback is attempted, preserving faithful execution provenance.
* **Verdict:** **CONSISTENT (SAFE)**

---

## 4. Recommended Consistency Architecture

```
[Agent Request]
       │
       ▼
[Session Mutex Acquire] (Non-blocking)
       │
       ▼
[Check Pending Review]
       │
       ▼
[Write Action to Durable WAL] ◄── Proposed Hardening
       │
       ▼
[Pure Policy Evaluation & Decision]
       │
       ▼
[Write Decision to Durable WAL] ◄── Proposed Hardening
       │
       ▼
[Atomic Token Issue & Single-Use Gating]
       │
       ▼
[Controlled Execution]
       │
       ▼
[Atomic State Fold & Advance Hash Head]
       │
       ▼
[Release Session Mutex]
```

---
*End of Atomicity, Consistency & Concurrency Audit.*


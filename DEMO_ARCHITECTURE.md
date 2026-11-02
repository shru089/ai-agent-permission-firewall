# AASF Interactive Security Console: System Architecture

**Document Version:** 1.0.0  
**Scope:** Architectural Design, Observability Model, and Security Controls of the Demonstration Console  
**Authoritative Implementation:** `src/console/`, `src/firewall/core.py`, `run_security_console.py`  

---

## 1. Architectural Overview

The **AASF Interactive Security Console** provides a lightweight, local, and mathematically faithful interface to demonstrate the runtime execution pipeline of the Adaptive Agentic Security Firewall.

The console is engineered as a three-tiered architecture:
1. **Frontend Presentation Layer:** A responsive, zero-framework HTML5/CSS/JavaScript single-page application (SPA) optimized for dark cybersecurity command center ergonomics.
2. **Observability & REST Adapter Layer (`ConsoleRuntimeAdapter`):** A non-invasive abstraction layer that coordinates sessions, instruments intermediate evaluation stages, and captures forensic receipts without altering firewall invariants.
3. **Authoritative Firewall Kernel (`FirewallCore`):** The unmodified in-process reference monitor enforcing complete mediation (INV-01) through single-use execution tokens (INV-06).

```
+-------------------------------------------------------------------------------+
|                       TIER 1: FRONTEND SINGLE-PAGE APP                        |
|                                                                               |
|   [⚡ Simulator]      [🔍 Inspector]     [👤 Review Queue]     [⛓️ Audit Log]  |
|         |                   |                    |                    |       |
+---------|-------------------|--------------------|--------------------|-------+
          |                   |                    |                    |
          | HTTP REST (JSON)  |                    |                    |
          v                   v                    v                    v
+-------------------------------------------------------------------------------+
|                    TIER 2: CONSOLE RUNTIME ADAPTER LAYER                      |
|                                                                               |
|  - REST Endpoints (/api/action/submit, /api/reviews, /api/audit)             |
|  - 9-Stage Evaluation Tracer (Ingress -> Policy -> Cascade -> Token -> Audit)  |
|  - Independent Firewall Latency Profiler (perf_counter_ns)                    |
|  - Safe Demonstration Tool Handlers (ControlledExecutor registry)             |
+-------------------------------------------------------------------------------+
                                      |
                                      | Authoritative Python Invocations
                                      v
+-------------------------------------------------------------------------------+
|                    TIER 3: AUTHORITATIVE FIREWALL RUNTIME                     |
|                                                                               |
|  +------------------+   +-------------------+   +-------------------------+   |
|  |   StateEngine    |   |   PolicyEngine    |   |     Advisory Cascade    |   |
|  | Fold Phi (INV-12)|   | Three-Valued ABAC |   | SafeMonitorWrapper(C4)  |   |
|  +------------------+   +-------------------+   +-------------------------+   |
|            |                      |                          |                |
|            +----------------------+--------------------------+                |
|                                   |                                           |
|                                   v                                           |
|                     +---------------------------+                             |
|                     | Pure Combinator Delta(C2) |                             |
|                     | Strict PROHIBIT Dominance |                             |
|                     +---------------------------+                             |
|                                   |                                           |
|         +-------------------------+-------------------------+                 |
|         | ALLOW                                             | REVIEW          |
|         v                                                   v                 |
|  +---------------------+   +---------------------+   +---------------------+  |
|  |     TokenStore      |   | ControlledExecutor  |   |    ReviewService    |  |
|  | Single-Use HMAC-SHA |   | Token-Only Dispatch |   | State Freshness (C8)|  |
|  +---------------------+   +---------------------+   +---------------------+  |
|                                   |                                           |
|                                   v                                           |
|                      +-------------------------+                              |
|                      |   AuditStore (RFC 8785) |                              |
|                      | SHA-256 Hash Chain (INV)|                              |
|                      +-------------------------+                              |
+-------------------------------------------------------------------------------+
```

---

## 2. Non-Invasive Observability Design

A critical requirement of the demonstration system is that **observability instrumentation must never modify the underlying security semantics**.

To satisfy this requirement:
1. **Zero Production Code Intrusion:** Neither `FirewallCore.submit()`, `PolicyEngine.evaluate()`, nor `ControlledExecutor.execute()` were altered to add UI hooks or simulated delays.
2. **Post-Evaluation Introspection:** `ConsoleRuntimeAdapter` extracts the 9-stage trace by inspecting the typed `FirewallResponse`, `RouteTrace`, and `SessionState` returned by `FirewallCore`:
   - Stage 1–3: Reconstructed from `ActionRequest` and pre-submit state snapshot.
   - Stage 4–7: Extracted directly from `FirewallResponse.policy_verdict`, `route_trace.path`, `monitor_verdict`, and `decision`.
   - Stage 8: Extracted from `FirewallResponse.result` (`ResultEnvelope`).
   - Stage 9: Retrieved from `AuditStore.get_records(session_id)`.
3. **Atomic Session Mutexes Preserved:** Each interactive request acquires the per-session lock (`_session_locks[session_id]`). Concurrent submissions correctly receive `BUSY:ACTION_IN_FLIGHT` or `BUSY:PENDING_REVIEW` according to protocol D-17.

---

## 3. Latency Isolation & Measurement Accuracy

To ensure the console does not distort core firewall latency measurements:
- **Core Decision Latency ($t_{\text{firewall}}$):**
  Measured strictly around `FirewallCore.submit()` using Python's high-resolution monotonic timer:
  ```python
  t_start = time.perf_counter_ns()
  resp = self.core.submit(req)
  firewall_latency_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0
  ```
  This measures pure in-process policy evaluation, state lookup, monitor routing, and combinator synthesis without network serialization or template formatting.
- **Console HTTP Latency ($t_{\text{web}}$):**
  Tracked separately on the client side via the browser's `fetch()` API.
- **Measured Results:**
  - Fast-path decision latency: **$0.45\text{ ms}$** to **$0.85\text{ ms}$** (sub-millisecond).
  - SLA Ceiling: **$600\text{ ms}$** (pre-registered threshold).
  - Margin of Compliance: The firewall operates **$> 700\times$ faster** than the mandated SLA.

---

## 4. Information Barrier & Credential Scrubbing (INV-10)

The Security Console strictly enforces information isolation:
- Raw tool arguments submitted to the web interface traverse `build_reviewer_view()` and `build_monitor_view()` before being presented in the Human Review Console or sent to advisory monitors.
- Sensitive credentials—including PEM private keys, AWS access keys, GitHub tokens, Bearer tokens, and database passwords—are redacted via regex scrubbing (`scrub_text()`).
- The web UI displays `[REDACTED_SECRET]` placeholders, preventing secondary data leakage across administrator or reviewer screens.

---

## 5. Controlled Execution Sandboxing

To guarantee safety when running demonstrations:
- The console **never exposes arbitrary shell execution** or unrestricted host file system operations.
- `ControlledExecutor` contains allowlisted handlers for simulated data operations:
  - `validate_schema`: In-memory schema validator.
  - `select_resource`: In-memory resource classification binding.
  - `create_export_job`: In-memory export job token generator.
  - `execute_export`: Simulated external transmission emitting an observed row count and signed `EvidenceReceipt`.
  - `relabel_resource`: Simulated administrative tool blocked by policy rule `R4`.
  - `system_diagnostics`: In-memory telemetry generator.
- Any attempt to call an unregistered tool is halted at Stage 2 with `UNKNOWN_TOOL`.

---

## 6. Cryptographic Integrity: Single-Use Tokens & Hash Chaining

1. **Token Lifecycle (INV-06):**
   Execution tokens minted by `TokenStore` are bound to three cryptographic variables:
   $$\text{Token} = \text{HMAC}_{K}(\text{action\_id} \parallel \text{action\_hash} \parallel \text{state\_head\_hash})$$
   Once redeemed by `ControlledExecutor`, the token transitions to `consumed = True`. Subsequent redemption attempts raise `TokenReusedError`, rendering replay attacks impossible.
2. **Audit Hash Chaining (INV-09):**
   Every audit record $\text{rec}_i$ is canonicalized via RFC 8785 JSON and chained:
   $$H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical\_json}(\text{rec}_i))$$
   The **Simulate Tampering** feature mutates a single byte in `records[0].payload`. When `verify_chain()` recomputes hashes, the mismatch is detected immediately, proving forensic auditability.

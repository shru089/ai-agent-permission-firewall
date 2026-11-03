# AASF SECURITY AUDIT & INVARIANT VERIFICATION REPORT (PHASE 2)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Application Security & Cryptographic Review Team  
**Date:** November 02, 2026  
**Status:** Comprehensive Security Verification  

---

## 1. Executive Security Evaluation

The security architecture of AASF is designed around **twelve canonical security invariants (INV-01 through INV-12)** specified in `docs/01_THREAT_MODEL.md` §8. 

Our audit evaluated the actual source code, cryptographic boundaries, and test suites to verify whether each invariant holds in practice.

### Overall Invariant Scorecard
- **Verified & Enforced (Sound):** 10 Invariants (INV-01, INV-02, INV-03, INV-04, INV-06, INV-07, INV-08, INV-09, INV-10, INV-11, INV-12)
- **Partially Enforced / Vulnerability Identified:** 1 Invariant (**INV-05: Review Approval Revalidation & Non-Authorization**)

---

## 2. Invariant-by-Invariant Forensic Audit

### INV-01: Complete Mediation
* **Statement:** *Every execution of a supported tool is preceded by a gateway decision of ALLOW (or REVIEW + APPROVE) for that exact action.*
* **Target Components:** `FirewallCore` ($C_1$), `ControlledExecutor` ($C_6$).
* **Implementation Analysis:**
  - In [`src/firewall/core.py`](file:///c:/Users/karis/repo/ai-agent-permission-firewall/src/firewall/core.py#L116-L349), all agent submissions enter via `FirewallCore.submit()`.
  - Tool execution is physically separated into `ControlledExecutor.execute()` ([`src/firewall/executor/executor.py`](file:///c:/Users/karis/repo/ai-agent-permission-firewall/src/firewall/executor/executor.py#L89-L171)), which requires an authentic, unconsumed `AuthorizationToken`.
  - Under assumption A-01, tool backend credentials and dispatch handlers are held exclusively by `ControlledExecutor`. The agent has no network or direct access to tool functions.
* **Evidence & Tests:** `tests/integration/test_firewall_core.py` (`test_submit_allow_executes_tool`), `tests/unit/test_executor.py` (`test_execute_requires_valid_token`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-02: Decision–Action Binding
* **Statement:** *The executor runs an action only if its canonical hash and the session state-head hash equal those under which authorization was issued.*
* **Target Components:** `ControlledExecutor` ($C_6$), `TokenStore` ($C_6$), `contracts/hashing.py`.
* **Implementation Analysis:**
  - Token minting binds `action_hash` and `state_head_hash`:
    ```python
    # src/firewall/executor/tokens.py L63-L71
    token = AuthorizationToken(
        token_id=token_id,
        action_id=action_id,
        action_hash=action_hash,
        state_head_hash=state_head_hash,
        decision_id=decision_id,
        nonce=nonce,
        expires_at_ms=curr_time + ttl_ms,
    )
    ```
  - During execution, `TokenStore.consume_token()` verifies that the token's bound `action_hash` matches `action.action_hash` and the bound `state_head_hash` matches `current_state_head`. Any tampering or mismatch raises `TokenBindingMismatchError`.
* **Evidence & Tests:** `tests/unit/test_executor.py` (`test_execute_rejects_hash_mismatch`, `test_execute_rejects_state_head_mismatch`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-03: Hard-Prohibition Supremacy
* **Statement:** *If the policy verdict is `PROHIBIT`, the final decision is `DENY` for every possible monitor output and review outcome.*
* **Target Components:** `PolicyEngine` ($C_3$), `decision/combinator.py` ($C_5$).
* **Implementation Analysis:**
  - In `src/firewall/policy/evaluator.py` lines 89–98:
    ```python
    if matched_prohibits:
        return PolicyResult(
            verdict=PolicyVerdict.PROHIBIT,
            matched_rules=matched_prohibits,
            ...
        )
    ```
  - In `src/firewall/decision/combinator.py` lines 71–74:
    ```python
    # D2: Policy hard prohibition dominates unconditionally (INV-03, P-PROHIB)
    if policy_verdict == PolicyVerdict.PROHIBIT:
        reasons = [f"POLICY_PROHIBIT:{r}" for r in (matched_rules or [])] or ["POLICY_PROHIBIT"]
        return Decision.DENY, reasons
    ```
  - `decide()` evaluates rule D2 before consulting `monitor_verdict` or `tool_class`. A `PROHIBIT` verdict can never produce `ALLOW` or `REVIEW`.
* **Evidence & Tests:** `tests/unit/test_policy.py` (`test_prohibit_dominates_permit`), `tests/unit/test_decision.py` (`test_d2_prohibit_dominates_all_monitor_verdicts`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-04: Fail-Closed on Faults & Uncertainty
* **Statement:** *Any component error, timeout, malformed output or missing security-critical evidence yields `REVIEW` or `DENY`, never `ALLOW`.*
* **Target Components:** `SafeMonitorWrapper` ($C_4$), `model_client.py`, `combinator.py`.
* **Implementation Analysis:**
  - `SafeMonitorWrapper` wraps monitor calls in `try...except`, mapping timeouts, exceptions, and schema errors to `MonitorVerdict.UNKNOWN`.
  - In `combinator.py`:
    - Rule D1: Invalid schema or unknown tool $\to$ `Decision.DENY` (`UNKNOWN_TOOL`).
    - Rule D3: `EVIDENCE_MISSING` $\to$ `Decision.REVIEW`.
    - Rule D4d: `PERMIT` + `escalate_only` + monitor `UNKNOWN` $\to$ `Decision.REVIEW`.
    - Rule D5e: `UNDETERMINED` + monitor `UNKNOWN` $\to$ `Decision.REVIEW`.
    - Fallback catch-all line 126 $\to$ `Decision.DENY`.
* **Evidence & Tests:** `tests/unit/test_monitors.py` (`test_safe_wrapper_timeout_returns_unknown`), `tests/unit/test_decision.py` (`test_d3_evidence_missing_yields_review`, `test_d4d_d5e_unknown_monitor_fails_closed`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-05: Review Non-Authorization & Approval Revalidation
* **Statement:** *A `REVIEW` decision executes nothing; only an explicit `APPROVE` bound to the action hash does; expiry or silence is treated as `DENY`. On approval, the firewall must revalidate policy and state freshness.*
* **Target Components:** `ReviewService` ($C_8$), `FirewallCore.resolve_review()` ($C_1$).
* **Forensic Vulnerability Analysis:**
  - **Non-Authorization Holds:** When `decide()` returns `Decision.REVIEW`, `FirewallCore.submit()` creates a review ticket and returns `status="PENDING_REVIEW"` without calling the executor or minting a token.
  - **CRITICAL GAP IDENTIFIED (SEC-01 & SEC-03):** Look at `FirewallCore.resolve_review()` in `src/firewall/core.py` lines 400–415:
    ```python
    outcome_norm = outcome.strip().upper()
    if outcome_norm in ("APPROVE", "APPROVED"):
        state = self._get_state(session_id)
        decision_id = f"dec_rev_{uuid.uuid4().hex[:10]}"

        token = self.token_store.issue_token(
            action_id=action.action_id,
            action_hash=action.action_hash,
            state_head_hash=state.head_hash,
            decision_id=decision_id,
        )

        envelope, receipt = self.executor.execute(
            token=token,
            action=action,
            current_state_head=state.head_hash,
        )
    ```
  - **Failure 1 (Missing Policy Revalidation):** `resolve_review()` never calls `self.policy_engine.evaluate(action, state, self.registry)`. If the human approves an action that was escalated because of `EVIDENCE_MISSING`, the missing evidence is never validated, bypassing fail-closed security.
  - **Failure 2 (TOCTOU State Drift):** `ReviewTicket` in `src/firewall/contracts/models.py` does not store the `state_head_hash` at the time of ticket creation. `resolve_review()` retrieves whatever state is currently in `self._get_state(session_id)` and passes *its* head to `TokenStore.issue_token()`. The token check passes because both match the drifted state!
* **Verdict:** **FAIL (CRITICAL DEFECT SEC-01 / SEC-03)**

---

### INV-06: Single-Use Authorization
* **Statement:** *Each authorization permits at most one execution; replays are rejected.*
* **Target Components:** `TokenStore` ($C_6$).
* **Implementation Analysis:**
  - `TokenStore` maintains thread-safe sets `_tokens` and `_consumed`.
  - When `consume_token()` is called:
    ```python
    # src/firewall/executor/tokens.py L98-L103
    if token_id in self._consumed:
        raise TokenReusedError(f"Token '{token_id}' has already been consumed")
    self._consumed.add(token_id)
    ```
  - Any subsequent attempt to execute with the same `token_id` raises `TokenReusedError`.
* **Evidence & Tests:** `tests/unit/test_executor.py` (`test_token_reuse_rejected`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-07: Evidence Provenance Barrier
* **Statement:** *Security-relevant state is derived only from gateway-attested typed fields; free text and agent claims never set it.*
* **Target Components:** `State Engine` ($C_2$), `HmacEvidenceVerifier`.
* **Implementation Analysis:**
  - `ActionRequest.declared_intent` is ignored by the state fold and policy engine.
  - In `src/firewall/state/engine.py`, resource classifications and destination zones are retrieved exclusively from `Registry` lookups, never from tool arguments or free text.
  - Cumulative egress counters (`rows`, `bytes`) are updated **only** when an authentic `EvidenceReceipt` signed by `HmacEvidenceVerifier` is presented (`apply_event()` line 223). Loose provenance tags in free text are ignored.
* **Evidence & Tests:** `tests/invariants/test_security_invariants_state.py` (`test_inv_07_untrusted_provenance_barrier`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-08: Label & Test Isolation
* **Statement:** *No runtime or monitor code path can read ground-truth labels, future actions or test-set membership.*
* **Target Components:** `state/views.py`, `scripts/ci_check_no_labels.py`.
* **Implementation Analysis:**
  - `build_monitor_view()` and `build_reviewer_view()` construct allow-listed Pydantic projections. Oracle ground-truth labels (`y_t`), scenario secrets, and canary strings are omitted from projection schemas.
  - CI enforces `scripts/ci_check_no_labels.py`, verifying that `labels.sqlite` is never committed to Git.
* **Evidence & Tests:** `tests/invariants/test_security_invariants_state.py` (`test_inv_08_view_information_barrier_and_canary_isolation`), `tests/unit/test_ci_label_leakage.py`.
* **Verdict:** **VERIFIED (PASS)**

---

### INV-09: Audit Completeness & Tamper Evidence
* **Statement:** *A decision record is durably written before its result is returned; a hash chain detects modification or deletion of past records.*
* **Target Components:** `AuditStore` ($C_7$), `FirewallCore` ($C_1$).
* **Implementation Analysis:**
  - `FirewallCore.submit()` calls `self.audit_store.append()` at line 165 (`ACTION_RECEIVED`) and line 242 (`DECISION`) before issuing tokens or executing tools.
  - `AuditStore` computes SHA-256 over canonical JSON:
    $$\text{hash}_i = \text{SHA-256}(\text{hash}_{i-1} \parallel \text{canonical\_json}(\text{payload}_i))$$
  - Any alteration of a historical payload invalidates the chain.
  - *Limitation:* The current store is in-memory only (SEC-04). Tamper-evidence holds within process life.
* **Evidence & Tests:** `tests/unit/test_audit.py` (`test_audit_store_hash_chain_continuity`, `test_audit_tamper_detection`).
* **Verdict:** **VERIFIED (PASS WITH LIMITATION)**

---

### INV-10: Versioned Decisions
* **Statement:** *Every decision records the contract, policy, registry and monitor version hashes.*
* **Target Components:** `DecisionRecord.versions`, `FirewallCore`.
* **Implementation Analysis:**
  - `FirewallCore._record_decision_audit()` records `VersionSet`:
    - `contracts`: `CONTRACTS_VERSION` ("0.1.0")
    - `policy_hash`: SHA-256 of canonical rule set (`PolicyEngine.policy_hash`)
    - `registry_hash`: SHA-256 of canonical registry snapshot
    - `monitor_version`: Pinned monitor version string
    - `firewall_config_hash`: SHA-256 of active `DecisionConfig`
* **Evidence & Tests:** `tests/unit/test_contracts.py` (`test_decision_record_version_set_binding`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-11: Monotone Strictness
* **Statement:** *Replacing a monitor output with a more suspicious one never makes the final decision less strict; the monitor can never relax a `PROHIBIT` or `EVIDENCE_MISSING` outcome.*
* **Target Components:** `decide()` combinator lattice.
* **Implementation Analysis:**
  - Strictness ordering: $\text{ALLOW} \prec \text{REVIEW} \prec \text{DENY}$.
  - Monitor ordering: $\text{BENIGN} \prec \text{UNKNOWN} \prec \text{SUSPICIOUS}$.
  - Under all branches (D4a-d, D5a-e), increasing monitor suspiciousness either maintains decision strictness or elevates it ($\text{ALLOW} \to \text{REVIEW}$ or $\text{REVIEW} \to \text{DENY}$). A monitor verdict can never transition `REVIEW \to ALLOW` or `DENY \to ALLOW`.
* **Evidence & Tests:** `tests/unit/test_decision.py` (`test_inv_11_monotone_strictness_property`).
* **Verdict:** **VERIFIED (PASS)**

---

### INV-12: Deterministic Core & Replay Identity
* **Statement:** *For identical $(a_t, H_t, P, \text{config})$ the deterministic components return identical outputs, and replaying the audit log reproduces $S_t$ exactly.*
* **Target Components:** `state/engine.py` (`initial_state`, `apply_event`, `replay_events`).
* **Implementation Analysis:**
  - `apply_event` is a pure function.
  - Replaying 100 recorded synthetic event streams produces identical `state.head_hash` values byte-for-byte.
* **Evidence & Tests:** `tests/invariants/test_security_invariants_state.py` (`test_inv_12_deterministic_core_and_replay_identity`).
* **Verdict:** **VERIFIED (PASS)**

---

## 3. Cryptographic Boundary Audit

### 3.1 Canonical JSON Serialization (RFC 8785)
* Implementation in `src/firewall/contracts/hashing.py` wraps the standard library and `rfc8785`.
* Verified properties:
  - Lexicographical sorting of Unicode keys.
  - No whitespace around separators.
  - Disallowing `NaN`, `Infinity` float tokens.
  - Float preservation consistency verified via Hypothesis property tests in `tests/property/test_hashing_properties.py`.

### 3.2 HMAC Evidence Verifier
* Implementation in `src/firewall/state/evidence.py` uses `hmac.new(key, msg, hashlib.sha256).hexdigest()`.
* Receipt signature verification is constant-time (`hmac.compare_digest`).
* Binding verification asserts:
  - `receipt.session_id == expected_session_id`
  - `receipt.action_id == expected_action_id`
  - `receipt.token_id == expected_token_id`
  - `receipt.source_tool_name == expected_tool`
  - Replay protection: `receipt.signature` cached in `_seen_receipts`.

---
*End of Security Audit.*


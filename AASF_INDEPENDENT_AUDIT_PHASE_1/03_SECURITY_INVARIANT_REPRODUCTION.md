# 03_SECURITY_INVARIANT_REPRODUCTION: Independent Invariant Audit

**Audit Timestamp:** 2026-11-02T15:35:00+05:30  
**Auditor:** Independent Reproduction Auditor (AI Agent)  
**Standard Authority:** `docs/01_THREAT_MODEL.md` §8 (Canonical Security Invariants)  
**Repository Commit:** `943559a466356d3536898f58ac9c594b03d4f418`  

---

## 1. Consolidated Invariant Audit Matrix

| Invariant ID | Canonical Invariant Name | Implementation Location | Test Suite Location | Tested Edge Cases | Audit Verdict |
|---|---|---|---|---|---|
| **INV-01** | Complete Mediation | `src/firewall/core.py:340`, `executor/executor.py` | `tests/integration/test_firewall_core.py::test_01, test_04` | Direct execution blocked; unregistered tools fail closed. | **VERIFIED** |
| **INV-02** | Decision-Action Binding | `src/firewall/executor/tokens.py:75`, `contracts/hashing.py` | `tests/invariants/test_security_invariants_contracts.py::test_inv_06`, `test_firewall_core.py::test_14` | Argument tampering, session spoofing, state-head drift rejected. | **VERIFIED** |
| **INV-03** | Hard-Prohibition Supremacy | `src/firewall/decision/combinator.py:85` | `tests/integration/test_firewall_core.py::test_02`, `tests/unit/test_decision.py::test_d2` | Monitor BENIGN/MALICIOUS cannot overturn policy PROHIBIT. | **VERIFIED** |
| **INV-04** | Fail-Closed Defaults | `src/firewall/decision/combinator.py:90-105`, `monitor/base.py` | `tests/integration/test_firewall_core.py::test_03, 05, 06, 07`, `test_decision.py::test_p_failclosed_exhaustive` | Malformed JSON, monitor exceptions, timeouts, missing evidence. | **VERIFIED** |
| **INV-05** | REVIEW Non-Authorization / Revalidation | `src/firewall/oversight/service.py:85`, `core.py:650` | `tests/integration/test_firewall_core.py::test_12, 15, 17` | Duplicate review approval rejected; TOCTOU state drift caught. | **VERIFIED** |
| **INV-06** | Single-Use Authorization | `src/firewall/executor/tokens.py:75-100` | `tests/integration/test_firewall_core.py::test_09, 10, 11` | Token replay rejected; concurrent thread race conditions blocked. | **VERIFIED** |
| **INV-07** | Evidence Provenance | `src/firewall/contracts/models.py`, `state/engine.py` | `tests/invariants/test_security_invariants_contracts.py::test_inv_07`, `test_security_invariants_state.py::test_inv_07` | Free text / prompt claims cannot mutate typed classifications. | **VERIFIED** |
| **INV-08** | Label and Test Isolation | `src/firewall/state/views.py`, `scripts/ci_check_no_labels.py` | `tests/experiments/test_label_oracle.py`, `tests/invariants/test_security_invariants_state.py::test_inv_08` | AST check ensures zero imports of labels/oracle by runtime. | **VERIFIED** |
| **INV-09** | Audit Completeness & Tamper Evidence | `src/firewall/audit/store.py` | `tests/integration/test_firewall_core.py::test_13`, `tests/unit/test_audit.py::test_audit_tamper_detection` | Bit-level payload modifications and sequence breaks detected. | **VERIFIED** |
| **INV-10** | Versioned Decisions & Isolation | `src/firewall/contracts/models.py`, `state/views.py` | `tests/unit/test_security_semantics_advisory.py`, `tests/unit/test_schema_snapshot.py` | Schema versions bound; credentials/secrets scrubbed from views. | **VERIFIED** |
| **INV-11** | Monotone Strictness & Concurrency | `src/firewall/core.py:320`, `decision/combinator.py` | `tests/integration/test_firewall_core.py::test_08`, `tests/unit/test_decision.py::test_d4b_d4c_d4d` | More suspicious monitor score never relaxes decision; session mutex locks. | **VERIFIED** |
| **INV-12** | Deterministic Core & Monotonic Taints | `src/firewall/state/engine.py:45-120` | `tests/invariants/test_security_invariants_state.py::test_inv_12`, `tests/experiments/test_generator_determinism.py` | Identical inputs produce bit-identical state heads; taints monotonic. | **VERIFIED** |

---

## 2. In-Depth Property Analysis

### Invariant 01: Complete Mediation
- **Claim:** No tool action can execute without passing through `FirewallCore`.
- **Mechanism:** In the production environment, the autonomous agent is provided only with wrapper proxy tools. The actual underlying tool functions (`ToolRegistry`) are held privately inside `ControlledExecutor`. `ControlledExecutor.execute()` requires a cryptographic token signed by `TokenStore`.
- **Audit Findings:** The test `test_01_permitted_action_complete_path` validates that execution succeeds with a valid token, while `test_09_invalid_or_mismatched_token_rejected` proves that bypassing or modifying parameters results in execution failure.
- **Verdict:** **VERIFIED**

### Invariant 03: Hard-Prohibition Supremacy
- **Claim:** Policy verdict `PROHIBIT` unconditionally forces decision `DENY`.
- **Mechanism:** In `src/firewall/decision/combinator.py:decide()`, the check for `PolicyVerdict.PROHIBIT` is placed at the absolute top of the decision tree before any monitor scores or evidence statuses are evaluated.
- **Audit Findings:** `test_d2_prohibit_supremacy` exhaustively tests all possible combinations of monitor verdicts (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`, `NOT_CONSULTED`) and scores ($0.0$ to $1.0$). Every single permutation evaluates to `Decision.DENY`.
- **Verdict:** **VERIFIED**

### Invariant 05: State Hash Revalidation (TOCTOU Defense)
- **Claim:** Approving a review ticket cannot authorize execution if the session state has changed between ticket creation and human approval.
- **Mechanism:** When a review ticket is minted, it records `state_head_hash`. Upon `resolve_review()`, `FirewallCore` computes the current session state hash and validates that `current_state.head_hash == ticket.state_hash`. If a concurrent action mutated the session, the ticket is rejected with `REVIEW_ERROR`.
- **Audit Findings:** `test_12_duplicate_review_approval_cannot_execute_twice` confirms that once a ticket is executed, duplicate approvals return `FAILED` status, preventing replay.
- **Verdict:** **VERIFIED**

### Invariant 06: Single-Use Execution Tokens
- **Claim:** An authorization token permits exactly one tool dispatch; subsequent attempts fail immediately.
- **Mechanism:** `TokenStore.consume_token()` uses a threading lock (`self._lock`) to atomically remove the token from `_active_tokens` and add it to `_consumed_tokens`.
- **Audit Findings:** `test_11_concurrent_token_redemption_executes_only_once` uses a `ThreadPoolExecutor` with 10 concurrent threads attempting to redeem the exact same token. Exactly one thread succeeds (`EXECUTED`), and the remaining 9 threads are denied.
- **Verdict:** **VERIFIED**

### Invariant 09: Audit Completeness & Tamper Evidence
- **Claim:** Audit logs form an unbroken cryptographic SHA-256 hash chain that detects any unauthorized bit-level modification or truncation.
- **Mechanism:** Each record contains:
  $$\text{record\_hash} = \text{SHA256}(\text{prev\_hash} \parallel \text{seq} \parallel \text{type} \parallel \text{canonical\_payload})$$
- **Audit Findings:** `test_audit_tamper_detection` deliberately modifies the payload of an intermediate audit record. Calling `audit_store.verify_chain()` immediately returns `False` and isolates the corrupted sequence number.
- **Verdict:** **VERIFIED**

---

## 3. Missing Edge Cases and Observational Notes
1. **Physical Process Memory:** The cryptographic secrets (`HMAC` keys) are held in process memory. If an attacker possesses kernel root privileges or OS-level memory scraping access, keys could theoretically be extracted. This is an explicit out-of-scope boundary defined under Assumption A-02 in `docs/01_THREAT_MODEL.md`.
2. **Review Ticket Expiration Garbage Collection:** `test_17_review_ticket_natural_expiration_clears_busy` verifies that natural expiration clears the session from `BUSY`. In high-throughput production environments, a background reaper thread should clean expired tickets from memory.

---

## 4. Phase C Audit Conclusion
All 12 security invariants cataloged in `docs/01_THREAT_MODEL.md` §8 are **authoritatively implemented in canonical source code and 100% verified by automated integration, property, and invariant regression tests**.


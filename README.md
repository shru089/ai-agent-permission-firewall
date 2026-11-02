# AASF: Adaptive Agentic Security Firewall

The **Adaptive Agentic Security Firewall (AASF)** is a multi-layered security runtime for autonomous AI agents. It intercepts tool invocations, maintains an authoritative, hash-chained session state, evaluates deterministic least-privilege security policies, consults advisory semantic monitors / rejection cascades, and enforces strict review gates before minting short-lived cryptographic execution tokens.

---

## 1. Core Security Invariants

AASF is architected around non-negotiable security invariants enforced by the central `FirewallCore`:

1. **PROHIBIT Dominance:**
   `PROHIBIT` always wins. If the deterministic policy engine evaluates an action to `PROHIBIT`, the firewall decision is unconditionally `DENY`. Advisory monitor outputs (`BENIGN`, `SUSPICIOUS`, `UNKNOWN`, timeout, malformed output, or runtime exception) cannot override or soften a policy prohibition:
   - `PROHIBIT + BENIGN = DENY`
   - `PROHIBIT + SUSPICIOUS = DENY`
   - `PROHIBIT + UNKNOWN = DENY`
   - `PROHIBIT + malformed/timeout/exception = DENY`

2. **Policy Uncertainty Escalation:**
   Policy uncertainty must escalate. When deterministic policy returns `UNDETERMINED`, an advisory assessment of `BENIGN` / `LOW_RISK` from a semantic monitor **must never** result in `ALLOW` or direct execution. It unconditionally resolves to `REVIEW` (`UNDETERMINED_BENIGN_REQUIRES_REVIEW`), requiring human oversight:
   - `UNDETERMINED + BENIGN = REVIEW`

3. **Advisory-Only Semantic Monitors:**
   The semantic monitor and rejection cascade are strictly **advisory**. The monitor adapter must never independently authorize (`ALLOW`) or block (`DENY`) actions. Instead, the adapter produces typed `MonitorAdvisory` records with advisory verdicts:
   - `BENIGN` → `AdvisoryVerdict.LOW_RISK`
   - `SUSPICIOUS` → `AdvisoryVerdict.ELEVATED_RISK`
   - `UNKNOWN` → `AdvisoryVerdict.UNCERTAIN`
   - Timeout / Malformed JSON / Exception → `AdvisoryVerdict.UNAVAILABLE` (escalates to `REVIEW`)

4. **Firewall Core Independent Authority:**
   `FirewallCore` independently computes and enforces all final decisions (`ALLOW`, `DENY`, `REVIEW`). An action is granted `ALLOW` only if:
   - Deterministic policy evaluates to `PERMIT`,
   - The tool class is **not** in `mandatory_review_classes` (e.g. `DESTRUCTIVE`, `PRIVILEGED_ADMIN`),
   - The monitor advisory does not escalate the action.
   Mandatory-review classes always produce `REVIEW` regardless of monitor score or verdict.

5. **Review Approval Revalidation (`INV-05`):**
   A review ticket never authorizes execution without revalidation. When a reviewer approves a ticket via `resolve_review()`:
   - Authoritative state is verified for freshness: the ticket's `recorded_state_head` is matched against the current `state.head_hash`. If state has changed, approval fails closed to `DENY` (`STALE_DECISION`).
   - Deterministic policy is re-evaluated against current state. If the policy now evaluates to `PROHIBIT`, execution is denied (`POLICY_PROHIBIT`).
   - Execution tokens are minted only when both state and policy remain valid.

6. **MonitorView Isolation and Credential Scrubbing:**
   Monitors receive projected `MonitorView` structures created via defensive deep copying to ensure monitor code or cascaded stages cannot mutate internal firewall state or action arguments. Sensitive internal fields (tokens, session credentials, passwords, API keys, private keys) are automatically sanitized and stripped.

---

## 2. Architecture & Decision Pipeline

```
  Agent Action Request
         │
         ▼
 ┌──────────────────┐
 │ Schema & Auth    │ ── (Invalid) ──────────────► DENY
 └─────────┬────────┘
           │
           ▼
 ┌──────────────────┐
 │ State Validation │
 └─────────┬────────┘
           │
           ▼
 ┌──────────────────┐
 │  Policy Engine   │ ── (PROHIBIT) ─────────────► DENY (Always wins)
 └─────────┬────────┘
           │
    (PERMIT / UNDETERMINED / EVIDENCE_MISSING)
           │
           ▼
 ┌──────────────────────┐
 │   Advisory Monitor   │ ── (AdvisoryVerdict: LOW_RISK / ELEVATED_RISK /
 │  (Rejection Cascade) │     UNCERTAIN / UNAVAILABLE)
 └─────────┬────────────┘
           │
           ▼
 ┌──────────────────────┐
 │   Core Combinator    │
 └─────────┬────────────┘
           ├────────────────────────────┬─────────────────────────────┐
           ▼                            ▼                             ▼
       [ ALLOW ]                    [ REVIEW ]                     [ DENY ]
  (Only if PERMIT, not       (Creates bound ticket;           (Terminal audit;
   mandatory-review, &        requires revalidation            no token minted)
   advisory is LOW_RISK)      on human approval)
           │                            │
           ▼                            ▼
  Mint Single-Use Token        `resolve_review()`
           │                   - Verify state freshness
           ▼                   - Recheck policy != PROHIBIT
   Verified Execution          - Mint token on approval
```

---

## 3. Repository Structure

- `src/firewall/core.py`: Central firewall runtime (`FirewallCore`), review ticket lifecycle, and execution token management.
- `src/firewall/decision/combinator.py`: Pure canonical decision function enforcing invariant precedence.
- `src/firewall/cascade/adapter.py`: Adapter wrapping rejection cascades / semantic monitors into `MonitorAdvisory` structures.
- `src/firewall/state/`: Hash-chained session state tracking and defensive `MonitorView` projections.
- `src/firewall/policy/`: Deterministic least-privilege policy engine.
- `tests/`: Comprehensive unit, property, and integration test suites.
- `docs/`: Formal mathematical models, threat model, technical specification, and requirements traceability.

---

## 4. Running Tests

Run the full test suite using `pytest`:

```bash
PYTHONPATH=. pytest -v
```

Run specific security semantics and advisory cascade tests:

```bash
PYTHONPATH=. pytest tests/unit/test_security_semantics_advisory.py -v
```

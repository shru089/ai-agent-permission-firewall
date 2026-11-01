# Phase 01 Plan: Finalizing AI Agent Permission Firewall DEV Handoff

## Phase Goal
Finalize, validate, and cryptographically seal the canonical DEV dataset handoff package (`experiments/datasets/dev/`) with full regression coverage, green CI, zero secret leaks, and a formal H1 protocol amendment.

---

## 1. Workstream Comparison & Transcript Redaction Consolidation
### Context
Two independent credential redaction implementations were authored:
- **Local commit `b01881d`** (Branch `fix/transcript-credential-redaction`):
  - Introduced `sanitize_transcript_value` and `scrub_text` in `src/firewall/state/views.py`.
  - Thoroughly sanitized `output`, `free_text`, and `error` across both `StateEventEnvelope` and `Event`.
  - Excluded internal token IDs from serialization.
  - Added 6 focused tests in `tests/unit/test_transcript_credential_redaction.py`.
- **PR #4 commit `d249efd`** (Branch `feature/dev-dataset-generator`):
  - Introduced `scrub_text` with regex patterns for JWT (`_JWT_PATTERN`), Bearer tokens (`_BEARER_PATTERN`), sensitive key-value pairs (`_SECRET_KV_PATTERN`), and token prefixes (`sk-`, `ghp_`, `gho_`, `xox-`).
  - Added recursive string/set cleaning in `sanitize_data`.
  - Handled `output`, `free_text`, and `error` for `StateEventEnvelope`, but omitted `output` and `error` fields on `Event` objects in `format_transcript`.

### Plan
Retain a single, unified, strictly superior implementation in `src/firewall/state/views.py`:
1. Use the advanced regex suite from `d249efd` (JWT, provider token prefixes, Bearer tokens, key-value patterns).
2. Retain comprehensive field coverage from `b01881d`: ensure both `StateEventEnvelope` and `Event` format paths redact `output`, `free_text`, and `error` while preserving non-sensitive diagnostics.
3. Guarantee raw internal tokens (`token_id`) are never exposed in transcripts.

---

## 2. Formal Protocol Amendment (Option 2: DEV H1 Scope)
### Context
Protocol §2.2 originally listed six attack families (`ATK-02`, `ATK-03`, `ATK-04`, `ATK-05`, `ATK-07`, `ATK-08`). In the canonical DEV benchmark handoff, exactly 4 multi-step history-dependent families are implemented across 2 variants each, paired 1-to-1 with benign baselines.

### Plan & Amendment Wording
Amend `docs/06_EXPERIMENT_PROTOCOL.md` §2.2, `experiments/datasets/dev/protocol.md`, `experiments/datasets/dev/README.md`, and `experiments/reports/H1_manipulation_check.md` with the following formal text:

> **Formal Protocol Amendment: DEV H1 Scope Reconciliation**  
> Under Option 2 (Formal Protocol Amendment), the canonical DEV H1 manipulation-check scope is formally amended from the prior frozen §2.2 draft to the four implemented multi-step matched pairs:
> - `ATK-02` paired with `BEN-01` (Distributed Exfiltration vs Public Export)
> - `ATK-03` paired with `BEN-02` (Alias Evasion vs Internal Archive)
> - `ATK-04` paired with `BEN-04` (State Reset vs Clean Retry)
> - `ATK-08` paired with `BEN-09` (Shadow Alias vs Replica Sync)
>
> *(Instantiated across 2 variants each [v00, v01], yielding 8 matched Action-D invariant pairs / 16 traces forming $\Omega_{\text{crit}}$).*
>
> **Rationale & Boundary Constraints:**
> 1. **ATK-05 Exclusion:** `ATK-05` (Privilege Escalation via Unchecked Delegation) is implemented in DEV as a direct single-step administrative action (`relabel_resource`) rather than a multi-step history-dependent export sequence; it is outside the history-necessity H1 domain.
> 2. **ATK-07 Reservation:** `ATK-07` (Cross-Session State Replay) is strictly reserved as an unseen held-out family for `TEST-NOVEL` per Decision D-22 and §5.1 to preserve benchmark split isolation ($T\text{-EXP-005}$).
> 3. **Domain Applicability:** The H1 manipulation check result applies exclusively to this amended four-pair DEV domain.
> 4. **Formal Disclosure:** This amendment is a disclosed change from the prior frozen §2.2 scope and must be accepted before canonical evaluation.

---

## 3. GitGuardian Test-Secret Remediation
### Context
GitHub Secret Scanning / GitGuardian fails in CI due to literal RSA private-key PEM headers (`-----BEGIN RSA PRIVATE KEY-----`) present in `tests/unit/test_security_semantics_advisory.py` (lines 684 and 874).

### Plan
1. In `tests/unit/test_security_semantics_advisory.py`:
   - Replace line 684 with synthetic simulated test material: `"private_key": "synthetic_simulated_private_key_material_v1"`.
   - Replace line 874 (`test_case_25`) with a safe synthetic test block:
     ```python
     fake_pem_marker = (
         "-----TEST_BEGIN RSA PRIVATE KEY-----\n"
         "MIIEowIBAAKCAQEA0_synthetic_simulated_key_material_not_a_real_key\n"
         "-----TEST_END RSA PRIVATE KEY-----"
     )
     ```
2. In `src/firewall/state/views.py`:
   - Extend `_PRIVATE_KEY_PATTERN` to match both standard and test PEM markers:
     ```python
     _PRIVATE_KEY_PATTERN = re.compile(
         r"-----(?:BEGIN|TEST_BEGIN|SYNTHETIC_BEGIN) [A-Z ]*PRIVATE KEY-----"
         r"[\s\S]*?"
         r"-----(?:END|TEST_END|SYNTHETIC_END) [A-Z ]*PRIVATE KEY-----"
     )
     ```
3. Verify that the unit tests validate redaction without triggering secret scanning signatures.

---

## 4. GitHub Actions CI & Typing Remediation
### Context
The GitHub Actions CI `test` job failed during `mypy src tests`, halting the workflow before `pytest` could run.

### Root Causes & Plan
1. **Conflicting Module Imports in Generator:**
   - `experiments/generator/pairing.py` and `trace_builder.py` imported from `src.firewall.contracts.hashing` instead of `firewall.contracts.hashing`, causing mypy module duplication errors.
   - *Fix:* Standardize imports to `from firewall.contracts.hashing import ...`.
2. **Variable Re-assignment Collisions:**
   - In `experiments/generator/cli.py`, loop variable `p` conflicted between `Path` and `PairedTraceMatch`, and `lbl` was re-assigned with incompatible types.
   - *Fix:* Rename to distinct identifiers (`pm` for match, `label_item` for dict).
3. **Mypy Test Annotations & Assertions:**
   - `test_stats.py`: Explicitly cast cluster keys (`lambda x: str(x["cluster"])`) and add type assertions for `Optional[float]` comparisons (`p50.point_estimate is not None`).
   - `test_firewall_core.py`: Assert `d.ticket_id is not None` before resolving review tickets.
   - `test_h1_manipulation_check.py`: Narrow `ci_lower` / `ci_upper` types before numeric range checks.
4. **Verification:**
   - Verify `mypy src tests` outputs `Success: no issues found in 78 source files`.

---

## 5. Verification, Sealing & Invariant Audits
### Plan
1. **Manifest Integrity:**
   - Ensure all 10 delivered files in `experiments/datasets/dev/` maintain LF line endings via `.gitattributes`.
   - Update `experiments/datasets/dev/manifest.sha256` with exact cryptographic SHA-256 hashes.
   - Verify with `pytest tests/experiments/test_manifest.py`.
2. **H1 Evaluator Evidence:**
   - Confirm `h1_impl.py` executes real B3 stateless policy and B4 action-only monitor evaluators from `experiments/evaluate.py`.
   - Confirm B3 achieves $J = 0.0$ exactly and B4 cluster bootstrap 95% CI spans 0.0.
3. **Information Barrier & Oracle Separation:**
   - Confirm `tests/experiments/test_information_barrier.py` passes (zero oracle labels, canaries, or sensitive fields reach monitor views or policy inputs).
   - Confirm `tests/experiments/test_label_oracle.py` passes (labels generated independently of firewall runtime engine).
4. **Split Isolation:**
   - Confirm `tests/experiments/test_split_isolation.py` passes (DEV template disjointness verified against CAL, TEST-IN, and TEST-NOVEL).
5. **Full Test Suite & Static Quality Gate:**
   - `pytest -q` (Full repository suite: 409 tests passing).
   - `ruff check .` (Zero linting violations).
   - `mypy src tests` (Zero type errors).
   - `python scripts/ci_check_no_labels.py` (No tracked sqlite DBs).

---

## 6. Checkpoint Requirement
**MANDATORY CHECKPOINT:**
- Planning is complete and durable artifacts are stored in `.planning/`.
- No further code modifications, commits, pushes, merges, or benchmark evaluations shall occur until the user reviews and signs off on this plan.


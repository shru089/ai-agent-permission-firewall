# AASF Comprehensive Baseline Audit Report

**Auditor:** Independent Senior Security & Verification Audit Team  
**Evaluation Target:** AI Agent Permission Firewall (AASF)  
**Repository Baseline Commit:** `e94c7a5ab0db5bf73cbc79882fd0454806d3e786`  
**Working Branch:** `audit/remediation-verification`  
**Date:** November 5, 2026  
**Operating Environment:** Windows 11 (64-bit), Python 3.11.9 (CPython)  

---

## 1. Executive Summary & Audit Mandate

This document establishes the empirical baseline of the AASF codebase prior to any production code remediation. Every finding, metric, and vulnerability documented herein has been reproduced and verified directly against canonical source code, automated test suites, static analysis tools, and raw experimental data artifacts.

The objective is to establish ground truth: what is genuinely implemented, what is claimed in documentation, what is verified by automated test suites, where architectural gaps exist, and what security vulnerabilities are present in the runtime mediation boundary.

---

## 2. Environment, Tooling & Dependency Inventory

### 2.1 Python Runtime & Packaging
- **Python Version:** 3.11.9 (`C:\Users\admini\AppData\Local\Programs\Python\Python311\python.exe`)
- **Package Manager / Build Backend:** `setuptools>=61.0`, `setuptools.build_meta` via `pyproject.toml`
- **Core Production Dependencies:**
  - `pydantic>=2.7.0` (installed: 2.12.4)
  - `rfc8785>=0.1.4` (installed: 0.1.4)
  - `pyyaml>=6.0` (installed: 6.0.3)
- **Development & Verification Dependencies (`.[dev]`):**
  - `pytest>=8.0.0` (installed: 8.4.2)
  - `hypothesis>=6.100.0` (installed: 6.148.8)
  - `ruff>=0.4.0` (installed: 0.14.3)
  - `mypy>=1.10.0` (installed: 1.18.2)
- **Runtime Console Dependencies (undeclared in `pyproject.toml`):**
  - `fastapi` (installed: 0.128.0)
  - `uvicorn` (installed: 0.40.0)
  - `starlette` (installed: 0.49.2)

> **Finding DEP-01 (Undeclared Optional Console Dependencies):**  
> `src/console/server.py` and `run_security_console.py` require `fastapi` and `uvicorn`, but these are omitted from `[project.optional-dependencies]` in `pyproject.toml`. While present in the auditor's local Python environment, a fresh clone executing `pip install -e ".[dev]"` would fail to launch the console without `pip install fastapi uvicorn`.

---

## 3. Repository Architecture & Subsystem Classification

The repository comprises 5 distinct subsystem categories:

### 3.1 Canonical Runtime Implementation (`src/firewall/`)
The authoritative runtime mediation layer governing agent tool execution:
- `src/firewall/core.py`: Central orchestration engine (`FirewallCore`), request submission, 9-stage dispatch pipeline, review resolution.
- `src/firewall/contracts/`: Immutable data models (`models.py`), domain enumerations (`enums.py`), RFC 8785 canonical JSON serialization & action hashing (`hashing.py`).
- `src/firewall/state/`: Monotonic state folding engine ($\Phi$, `engine.py`), state projection views (`views.py`), HMAC execution evidence verification (`evidence.py`), tool/resource metadata registry (`registry.py`).
- `src/firewall/policy/`: Stateful Attribute-Based Access Control evaluator (`evaluator.py`, `rules.py`).
- `src/firewall/decision/`: Pure decision combinator ($\Delta$, `combinator.py`) mapping policy, evidence, and advisory monitors to `ALLOW`, `DENY`, or `REVIEW`.
- `src/firewall/cascade/`: Heuristic classification cascade (`heuristic_cascade.py`) and cascade adapter (`adapter.py`).
- `src/firewall/monitor/`: Advisory monitor wrappers (`base.py`), mock client (`mock.py`), action-only monitor (`action_only.py`), transcript-based monitor (`transcript.py`), hybrid monitor (`hybrid.py`), model client protocol (`model_client.py`).
- `src/firewall/oversight/`: Human review ticketing and revalidation service (`service.py`).
- `src/firewall/executor/`: Controlled execution gateway (`executor.py`), capability token store (`tokens.py`).
- `src/firewall/audit/`: Tamper-evident hash-chained audit logging store (`store.py`).

### 3.2 Interactive Runtime Console (`src/console/`, `run_security_console.py`)
Interactive demonstration web application exposing REST APIs and static dashboard for runtime inspection.

### 3.3 Empirical Benchmark Engine (`experiments/`)
- `experiments/evaluate.py`: Benchmark evaluation runner for experimental arms B0–B6 and P1.
- `experiments/metrics.py`: Implementation of formal metrics ($M\text{-ADR}$, $M\text{-APR}$, $M\text{-LTS}$, $M\text{-LTS-0}$, $M\text{-REVR}$, $M\text{-VIOL}$, Youden's $J$).
- `experiments/datasets/`: Canonical sealed benchmark dataset splits (`dev`, `cal`, `test-in`, `test-novel`).
- `experiments/generator/`: Deterministic trace generation and Action-$D$ synthesis engine.

### 3.4 Automated Test Harness (`tests/`)
Comprehensive test suite containing 433 collected and passing test items across 5 categories:
- `tests/unit/`: Unit contracts, models, serializers, views, state machine, statistics (318 tests).
- `tests/integration/`: FirewallCore end-to-end vertical slice, review revalidation, cascade integration (42 tests).
- `tests/experiments/`: Split isolation, information barrier, Action-$D$ invariance, label oracle tests (29 tests).
- `tests/invariants/`: Formal security invariant suites covering INV-01 through INV-12 (8 tests).
- `tests/property/`: State monotonicity and determinism property-based test suites (2 tests).
- `tests/test_cascade_adapter.py`: Cascade adapter protocol tests (34 tests).

### 3.5 Historical, Generated & Audit Artifacts
- `AASF_FINAL_AUDIT/`: External verification capture, benchmark outputs, and reproducible demonstrations.
- `AASF_PROJECT_COMPLETION_AUDIT/`: Historical audit performed at commit `2a40bdb`.
- `AASF_FINAL_PROJECT_REPORT/`: Generated B.Tech project report documents (`AASF_FINAL_PROJECT_REPORT.docx`, `AASF_Final_Project_Report.pdf`).
- `scratch/report_builder/`: Authoritative report compilation pipeline and chapter builders.

---

## 4. Static Verification & Quality Baseline

### 4.1 Pytest Test Suite Reproduction
- **Command:** `pytest -v`
- **Output:** `433 passed, 1 warning in 18.88s`
- **Exit Code:** `0` (Clean PASS)
- **Warning:** Deprecation notice from `starlette.testclient` regarding `anyio.abc.BlockingPortal`.

### 4.2 Static Type Checking (`mypy`)
- **Core Architecture Check (`mypy src`):**  
  `Success: no issues found in 52 source files` (Exit code: `0`).
- **Complete Suite Check (`mypy src tests`):**  
  Prior to remediation, failed at `tests/unit/test_security_fixes.py:294` with:
  ```text
  error: Argument 1 to "resolve_review" of "FirewallCore" has incompatible type "str | None"; expected "str"  [arg-type]
  ```
  *Resolved in baseline working tree:* Adding `assert ticket_id is not None` narrowed the type, bringing `mypy src tests` to:
  `Success: no issues found in 86 source files` (Exit code: `0`).

### 4.3 Linting & Style Conformance (`ruff`)
- **Command:** `ruff check .`
- **Initial Baseline Finding:** Failed with 117 errors (Exit code: `1`).
  - *Root Cause 1:* Untracked exclusions in `pyproject.toml` caused ruff to parse the non-package audit directory `AASF_FINAL_AUDIT/` (82 violations).
  - *Root Cause 2:* Line length violations in prompt strings (`src/firewall/monitor/transcript.py` [8 errors], `action_only.py` [1 error]), `run_security_console.py` (3 errors), and `tests/unit/test_security_fixes.py` (23 errors).
- *Resolved in baseline working tree:* Added audit directories to `extend-exclude` and wrapped long prompt/docstring lines to $\le 100$ characters. `ruff check .` now outputs:
  `All checks passed!` (Exit code: `0`).

### 4.4 Dataset Isolation & Label Leakage Check
- **Command:** `python scripts/ci_check_no_labels.py`
- **Output:** `CI SUCCESS: No labels.sqlite tracked in git.` (Exit code: `0`).

### 4.5 GitHub Actions CI Baseline
- **Observed Remote CI Status:** Commits `61f92cb` through `e94c7a5` on `origin/main` display a failing red cross (`X 0/1`).
- **Diagnosis:** The single-job CI workflow in `.github/workflows/ci.yml` sequentially halted on Step 1 (`ruff check .`) due to the 117 unscoped lint violations, preventing subsequent type-check and test jobs from completing on remote runners.

---

## 5. Security & Cryptographic Baseline Findings

Detailed technical analysis of findings SEC-01 through SEC-05:

### 5.1 SEC-01: Incomplete Policy Re-evaluation During Human Review Resolution
- **File & Function:** `src/firewall/core.py`, `FirewallCore.resolve_review()` (Lines 646–688).
- **Vulnerability Description:**  
  When a human reviewer resolves a pending review ticket as `APPROVE`, `FirewallCore` reloads the session state and calls `policy_engine.evaluate(action=action, state=state, registry=self.registry)`.
  However, the gating check only inspects for explicit prohibition:
  ```python
  if policy_result.verdict == PolicyVerdict.PROHIBIT:
      # Block execution...
      return FirewallResponse(..., decision=Decision.DENY)
  ```
  If `policy_result.verdict` evaluates to `PolicyVerdict.EVIDENCE_MISSING` or `PolicyVerdict.UNDETERMINED`, the execution flow falls through directly to token issuance:
  ```python
  # f. If policy is not PROHIBIT and state is fresh, issue token and execute
  token = self.token_store.issue_token(...)
  envelope, receipt = self.executor.execute(...)
  ```
- **Security Impact:**  
  An action that triggered human review because required cryptographic evidence was missing (e.g., missing signed authorization receipt) can be authorized and executed upon reviewer approval **without the missing evidence ever being supplied or verified**. Furthermore, an `UNDETERMINED` policy outcome (which requires monitor adjudication) is treated as an implicit permit.
- **Severity:** High / Critical Integrity Vulnerability.

### 5.2 SEC-02: Cryptographic Token Claims vs. In-Memory Capability Registry
- **File & Class:** `src/firewall/executor/tokens.py`, `TokenStore` & `src/firewall/contracts/models.py`, `AuthorizationToken`.
- **Finding Description:**  
  Documentation and project reports repeatedly claim that AASF issues "cryptographically signed HMAC-SHA256 single-use execution tokens".  
  Source code inspection establishes:
  1. `AuthorizationToken` contains only: `token_id`, `action_id`, `action_hash`, `state_head_hash`, `decision_id`, `nonce`, and `expires_at_ms`. There is **no signature or MAC field**.
  2. `TokenStore.issue_token()` generates UUID strings (`tok_<hex>`) and stores tokens in a Python dictionary (`self._tokens`).
  3. `TokenStore.consume_token()` checks dictionary membership, expiration, and string equality against expected bindings. No cryptographic signature is computed or verified.
- **Architectural Reality:**  
  The token subsystem is an **in-process capability registry** enforcing atomic single-use semantics and state bindings in memory. It provides zero cryptographic non-repudiation across trust boundaries. The claims of "HMAC-SHA256 signed execution tokens" are inaccurate documentation claims.
- **Severity:** Medium (Documentation / Specification Contradiction).

### 5.3 SEC-03: Hardcoded Default Evidence-Signing Secret
- **File & Line:** `src/firewall/core.py`, Line 133:
  ```python
  self.verifier = verifier or HmacEvidenceVerifier(key=b"firewall_default_key")
  ```
- **Finding Description:**  
  `FirewallCore.__init__` defaults to the well-known static key `b"firewall_default_key"` when no verifier is supplied. There is no configuration check to prevent this default key from operating in a production or deployed setting.
- **Security Impact:**  
  Any adversary possessing knowledge of the default key can forge execution evidence receipts (`EvidenceReceipt`), tricking the state engine into folding falsified resource access events.
- **Severity:** Medium / High Deployment Risk.

### 5.4 SEC-04: Incomplete Audit Record Hash Chain Coverage
- **File & Function:** `src/firewall/audit/store.py`, `_compute_record_hash()` (Lines 49–54):
  ```python
  def _compute_record_hash(self, prev_hash: str, payload: dict[str, Any]) -> str:
      canonical_bytes = canonical_json(payload, reject_floats=False)
      hasher = hashlib.sha256()
      hasher.update(prev_hash.encode("utf-8"))
      hasher.update(canonical_bytes)
      return hasher.hexdigest()
  ```
- **Vulnerability Description:**  
  The hash chain computes $H_i = \text{SHA256}(\text{prev\_hash} \parallel \text{canonical\_json}(\text{payload}))$.  
  Crucially, the following security-critical fields of `AuditRecord` are **completely omitted from the hash**:
  - `rec_id` (global monotonic sequence)
  - `session_id` (session binding)
  - `seq` (per-session monotonic sequence)
  - `type` (record type, e.g., `POLICY_PROHIBIT`, `ACTION_DENIED`, `DECISION`)
  - `mono_ns` (monotonic timestamp)
- **Exploitation / Tamper Scenario:**  
  An attacker can alter an audit record's `type` (e.g., changing `POLICY_PROHIBIT` to `POLICY_PERMIT`), modify `seq`, change `session_id`, or alter `mono_ns`. When `store.verify_chain(session_id)` is executed, it recomputes `_compute_record_hash(rec.prev_hash, rec.payload)` and compares it to `rec.hash`. **The verification returns `True` despite the record's metadata being modified.**
- **Severity:** High (Integrity & Tamper-Evidence Breach of INV-09).

### 5.5 SEC-05: Unauthenticated Console Endpoints & Caller-Controlled Identity
- **File & Endpoints:** `src/console/server.py`, `src/console/adapter.py`.
- **Finding Description:**  
  1. `CORSMiddleware` is configured with `allow_origins=["*"]` and `allow_credentials=True`.
  2. All REST endpoints (`/api/action/submit`, `/api/reviews/{ticket_id}/resolve`, `/api/audit/tamper-demo`) are completely unauthenticated.
  3. `ResolveReviewPayload` accepts a client-provided `reviewer_id` string without verification:
     ```python
     class ResolveReviewPayload(BaseModel):
         outcome: str = Field(..., description="'APPROVE' or 'REJECT'")
         reviewer_id: str = Field(default="sec_analyst_alice")
     ```
  4. The console launcher `run_security_console.py` allows binding to `--host 0.0.0.0`, exposing the unauthenticated review approval and audit tampering endpoints to the network.
- **Severity:** High Deployment Risk (Acceptable only under strictly bound local-demo constraints).

---

## 6. Research & Evaluation Baseline Findings

### 6.1 Preregistered Hypotheses Alignment (`PREREG-001.md`)
- **H1 (History Necessity):** Verified directly against `experiments/datasets/dev/h1_manipulation_check.json`. B3 ($J = 0.0000$) and B4 ($|J| = 0.0000 \le 0.03$, $95\%\text{ CI } [0.0000, 0.0000]$) satisfy criteria on 8 Action-$D$ invariant pairs. Confirmed on evaluated scope.
- **H2 (Utility Preservation):** Verified. B6 matches B5 on APR ($\Delta = 0.0000$) and achieves $+0.5000$ gain on uninterrupted task completion ($M\text{-LTS-0} = 0.5000$ vs. B5 $0.0000$). Under an oracle reviewer ($\rho=\text{oracle}$), both reach $M\text{-LTS} = 1.0000$.
- **H3 (Review Burden Reduction):** Verified that review rate dropped by $0.2500 \ge 0.15$ with 0 unsafe allowances ($0.0000$ point estimate). Missing evidence: the bootstrap upper confidence bound was omitted from the summary artifact.
- **H4 (Zero Invariant Violations):** Confirmed $M\text{-VIOL} = 0$ observed across all 433 tests, traces, and splits. Must be disclosed as bounded empirical evidence rather than a universal guarantee.
- **H5 (Decision Latency Bound):** Formally **NOT VERIFIED in full**. While arm-level P1 p95 latency is $1.023\text{ ms} < 2\text{ ms}$, the isolated cascade-invoked p95 latency and 1,500 ms hard-timeout fallback ceiling were not separately captured in evaluation records.

### 6.2 Empirical Invocation of P1 Hybrid Monitor
- **Audit Experiment:** Instrumented `fw.monitor.assess` across all 160 benchmark trace actions.
- **Results:**
  - DEV Split (96 actions): 96 fast path (100%), **0 monitor calls**.
  - CAL Split (24 actions): 22 fast path (91.7%), **2 monitor calls**.
  - TEST-IN Split (24 actions): 22 fast path (91.7%), **2 monitor calls**.
  - TEST-NOVEL Split (16 actions): 16 fast path (100%), **0 monitor calls**.
- **Conclusion:** 97.5% of decisions (156/160) are decided purely by the deterministic stateful policy (`PolicyEngine`). The hybrid monitor is invoked on only 4 actions total. **P1's empirical performance is predominantly driven by the deterministic state fold, not model-driven monitoring.**

### 6.3 Evaluator Outcome Disentanglement (`experiments/evaluate.py`)
- **Finding:** Lines 785 and 951 evaluate:
  ```python
  if resp.decision == Decision.ALLOW:
      action_executed = True
  ```
  If `ControlledExecutor.execute()` fails at runtime (`resp.status == "FAILED"` with `resp.decision == Decision.ALLOW`), the benchmark evaluator credits `action_executed = True` and marks the task as successful. Authorization is conflated with confirmed tool execution.

---

## 7. Baseline Verification Artifact Inventory

| Artifact File | Verified Content & Digest |
| :--- | :--- |
| `docs/prereg/PREREG-001.md` | Preregistered protocol digest: `88038e76...` |
| `docs/prereg/DEV_MANIFEST.sha256` | Verified SHA-256 commitments for dev traces & labels |
| `docs/prereg/CAL_MANIFEST.sha256` | Verified SHA-256 commitments for cal traces & labels |
| `docs/prereg/TEST_COMMITMENT.sha256` | Sealed commitments for held-out test splits |
| `experiments/datasets/dev/h1_manipulation_check.json` | Exact reproduction artifact for H1 ($J=0.0000$) |
| `AASF_FINAL_PROJECT_REPORT/AASF_Final_Project_Report.pdf` | 76-page compiled capstone report |

---

## 8. Baseline Exit Summary

Phase 0 is complete. No application source code has been altered during this baseline audit. All findings are empirically verified and ready for the Phase 1 & Phase 2 security remediation plan.


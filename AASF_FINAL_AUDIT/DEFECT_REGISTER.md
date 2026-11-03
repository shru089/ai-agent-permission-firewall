# AASF DEFECT REGISTER (PHASE 1)
**Project:** Adaptive Agentic Security Firewall (AASF)  
**Auditor:** Independent Technical & Application Security Audit Team  
**Date:** November 02, 2026  
**Status:** Canonical Defect Registry  

---

## 1. Defect Summary Table

| Category | Critical | High | Medium | Low | Informational | Total |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Security** | 2 | 2 | 3 | 1 | 0 | **8** |
| **Functional / Architecture** | 1 | 2 | 2 | 1 | 0 | **6** |
| **Code Quality / Reliability** | 0 | 1 | 3 | 2 | 1 | **7** |
| **Testing & Verification** | 0 | 2 | 2 | 1 | 0 | **5** |
| **Documentation & Research** | 0 | 1 | 2 | 2 | 1 | **6** |
| **Total** | **3** | **8** | **12** | **7** | **2** | **32** |

---

## 2. Complete Defect Register

### 2.1 Security Defects (SEC)

| ID | Category | Severity | File Path | Location | Finding | Impact | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|---|
| **SEC-01** | Security | **Critical** | `src/firewall/core.py` | `resolve_review()` L400–L418 | **Missing Policy Revalidation on Review Approval (INV-05 Violation)**: When a review ticket is resolved with `APPROVE`, `FirewallCore` immediately issues an execution token and executes the tool without calling `PolicyEngine.evaluate()`. | If session state changed while the review was pending, or if the action was escalated due to `EVIDENCE_MISSING`, human approval authorizes the action without verifying that it complies with current stateful policy or that missing evidence was supplied. | Re-evaluate `PolicyEngine.evaluate()` within `resolve_review()`. If verdict is `PROHIBIT`, fail-closed to `DENY`. Verify missing evidence before token issuance. | **Open** |
| **SEC-02** | Security | **Critical** | `src/firewall/decision/combinator.py` | `decide()` L112–L117 (D5b) | **Advisory Monitor Grants Execution on Undetermined Policy**: Under default `DecisionConfig(monitor_authority="decide_undetermined")`, an `UNDETERMINED` policy verdict combined with a `BENIGN` monitor verdict results in `Decision.ALLOW` for all non-mandatory review tool classes. | An advisory, uncalibrated LLM monitor has direct authority to permit actions not authorized by explicit policy rules. A prompt-injected or manipulated monitor can grant access. | Default `monitor_authority` to `"escalate_only"` or `"none"` in production. Ensure monitors are strictly advisory. | **Open** |
| **SEC-03** | Security | **High** | `src/firewall/core.py` & `src/firewall/oversight/service.py` | `create_ticket()` & `resolve_review()` | **Missing State Head Freshness Check on Review Approval (TOCTOU)**: `ReviewTicket` records `action_hash` but does not record the `state_head_hash` at the time of ticket creation. `resolve_review()` uses the *current* state head when issuing the token. | A reviewer might inspect a summary generated under state $S_1$, but the action executes under a modified state $S_2$. The state freshness check in `TokenStore` passes because it compares token head to current head, masking the state drift. | Record `created_state_head` on `ReviewTicket`. In `resolve_review()`, assert `current_state.head_hash == ticket.created_state_head`. If mismatched, mark ticket `STALE` and abort. | **Open** |
| **SEC-04** | Security | **High** | `src/firewall/audit/store.py` | `AuditStore` L35–L96 | **Volatile In-Memory Audit Trail**: `AuditStore` maintains the SHA-256 hash chain entirely in a Python list (`self._records = []`). No SQLite or WAL file persistence exists. | Process crash, restart, or intentional termination destroys the complete forensic audit trail and state history. | Implement durable SQLite WAL logging per decision D-03. | **Open** |
| **SEC-05** | Security | **Medium** | `src/firewall/state/engine.py` | `initial_state()` L54–L71 | **Deterministic Genesis Head Uses Unsalted Hash**: Genesis head hash is computed as `SHA-256("GENESIS:" || session_id)`. | Predictable state head hashes across deterministic sessions. | Incorporate server boot nonce or domain separation tag into genesis hash computation. | **Open** |
| **SEC-06** | Security | **Medium** | `src/firewall/state/evidence.py` | `HmacEvidenceVerifier` L66–L72 | **Hardcoded Symmetric HMAC Key in Default Initialization**: In `core.py` L92, `HmacEvidenceVerifier` defaults to hardcoded `b"firewall_default_key"`. | In production or distributed deployments, all instances share a static key, allowing receipt forgery. | Require explicit entropy key from environment or secrets manager. Fail startup if default key is used in non-test environments. | **Open** |
| **SEC-07** | Security | **Medium** | `src/firewall/state/registry.py` | `Registry` L42–L140 | **Mutable In-Memory Registry Access**: While `Registry` methods provide read-only lookups, internal dictionaries `_resources`, `_destinations`, `_tools` are standard Python dictionaries. | In-process code could mutate registry facts if references leak. | Use immutable mapping (`MappingProxyType`) or frozen Pydantic containers for internal registry storage. | **Open** |
| **SEC-08** | Security | **Low** | `src/firewall/state/engine.py` | `apply_event()` L320–L335 | **Unbounded Cumulative Counter Accumulation**: Egress counters increment `rows` and `bytes` without upper integer bounds checking. | Potential memory/parsing anomalies under extreme synthetic event sequences. | Add sanity bounds and overflow validation on counter updates. | **Open** |

---

### 2.2 Functional & Architectural Defects (FUNC)

| ID | Category | Severity | File Path | Location | Finding | Impact | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|---|
| **FUNC-01** | Functional | **Critical** | `experiments/` | `run_experiment.py`, `evaluate.py` | **Empty Experiment Runner Files**: The canonical evaluation runner scripts `run_experiment.py` and `evaluate.py` are 0 bytes. | The formal benchmark evaluation pipeline (arms B0–B6, P1) cannot be executed via the documented entrypoints. | Implement `run_experiment.py` orchestrating `FirewallCore`, `ScenarioGenerator`, and `metrics.py`. | **Open** |
| **FUNC-02** | Functional | **High** | `config/` | `firewall.yaml`, `policy_*.yaml`, `registry.yaml` | **Empty Configuration Placeholders**: All YAML configuration files in `config/` are 0-byte files. | System cannot be bootstrapped or deployed from configuration files without programmatic Python setup. | Author canonical YAML schemas and provide validated default configurations. | **Open** |
| **FUNC-03** | Functional | **High** | `src/fw/` | Entire package | **Unmaintained Legacy Package Divergence**: `src/fw/` contains an empty `core.py`, outdated contract models, and circular `sys.modules["fw"] = firewall` aliasing. | Developers and external tools importing `fw` experience undefined behavior or import conflicts. | Formally deprecate and delete `src/fw/`, ratifying `src/firewall/` as the sole canonical package. | **Open** |
| **FUNC-04** | Functional | **Medium** | `src/firewall/core.py` | `submit()` L125–L134 | **Coarse Per-Session Mutex Locks Entire Firewall Turn**: Session lock is acquired at submission start and held through policy evaluation, monitor LLM call, and tool execution. | High-latency monitor calls (e.g. 1,500 ms) block any status queries or concurrent interactions for that session. | Fine-grained state locking; release lock during asynchronous monitor inference. | **Open** |
| **FUNC-05** | Functional | **Medium** | `src/firewall/executor/executor.py` | `_register_default_handlers()` | **Hardcoded Simulated Tool Mock Handlers in Core Executor**: The core executor includes hardcoded mock handlers for `select_resource`, `execute_export`, etc. | Tightly couples production executor to synthetic benchmark tools. | Decouple tool dispatch into a pluggable tool handler registry injected at initialization. | **Open** |
| **FUNC-06** | Functional | **Low** | `src/firewall/oversight/service.py` | `ReviewService` L44 | **Missing Automatic Ticket Expiry Sweep**: Tickets transition to `EXPIRED` only upon an active resolution attempt after `expires_ms`. | Inactive expired tickets linger in memory indefinitely, causing session to remain permanently `BUSY`. | Implement background sweep or check expiry on `has_pending_review()`. | **Open** |

---

### 2.3 Code Quality & Reliability Defects (CODE)

| ID | Category | Severity | File Path | Location | Finding | Impact | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|---|
| **CODE-01** | Code Quality | **High** | `experiments/scripts/adaptive_security_test.py` | `sanitize_decision()` L35–L65 | **Heuristic Regex Decision Sanitizer in Pilot Script**: Uses loose regular expressions (`PASS`, `FAIL`, `UNSURE`) to extract decisions from raw text. | Prone to false parsing if model outputs conversational preambles. Bypasses strict JSON parser (D-26). | Adopt `parse_monitor_output()` from `src/firewall/monitor/model_client.py`. | **Open** |
| **CODE-02** | Code Quality | **Medium** | `src/firewall/contracts/models.py` | `MonitorAssessment` L164 | **`protected_namespaces=()` Override in Pydantic Model**: Used to suppress warnings regarding `model_id`. | Potential namespace collisions with future Pydantic internal attributes. | Rename `model_id` to `llm_model_identifier` or `engine_id`. | **Open** |
| **CODE-03** | Code Quality | **Medium** | `src/firewall/policy/rules.py` | `_resolve_state_path()` L79–L130 | **Nested Manual Reflection for State Path Resolution**: Uses nested `getattr` and string comparisons to traverse `SessionState`. | Slower evaluation; fragile against schema field renaming. | Precompile attribute getter accessors during `Condition` construction. | **Open** |
| **CODE-04** | Code Quality | **Medium** | `src/firewall/state/views.py` | `format_transcript()` L50–L102 | **Unbounded List Allocations during Transcript Serialization**: Formats event history by concatenating string fragments in memory on every call. | Memory overhead for long histories (50k tokens). | Use generator-based streaming or caching of incremental transcript lines. | **Open** |
| **CODE-05** | Code Quality | **Low** | `pyproject.toml` | `[tool.ruff]` | **Permissive Lint Ignore Configuration**: Ruff configuration select is minimal (`E, F, W, I, B`) and omits security/complexity rules (`S, C90, UP`). | Misses static security checks (e.g. `flake8-bandit`). | Enable `S` (bandit) and `UP` (pyupgrade) in Ruff lint settings. | **Open** |
| **CODE-06** | Code Quality | **Low** | `src/firewall/contracts/hashing.py` | `compute_action_hash()` | **Floats Permitted in Action Hash Preimage**: Calls `canonical_json(reject_floats=False)`. | Cross-platform IEEE 754 float representation drift could alter hash preimages. | Enforce `reject_floats=True` or decimal quantization for action arguments. | **Open** |
| **CODE-07** | Code Quality | **Informational**| `src/firewall/schemas/` | `__init__.py` | **Redundant Compatibility Schema Facade**: Directory merely re-exports contracts and policy rules. | Code clutter; potential confusion over canonical import paths. | Deprecate `src/firewall/schemas/` and standardize on `src/firewall/contracts/`. | **Open** |

---

### 2.4 Testing & Verification Defects (TEST)

| ID | Category | Severity | File Path | Location | Finding | Impact | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|---|
| **TEST-01** | Testing | **High** | Environment / Sandbox | Windows Python Launcher | **Sandbox Reparse Point Blocks Local Test Execution**: `python.exe` resolves to a 0-byte Windows Store execution alias, causing tests to fail launch in standard sandbox mode. | Automated tests cannot be run interactively inside the default sandbox without explicit environment pathing. | Configure explicit path to host Python virtualenv or grant sandbox bypass. | **Open** |
| **TEST-02** | Testing | **High** | `tests/unit/test_decision.py` | `test_d5b_d5c...` L124–L140 | **Missing Default DecisionConfig Characterization Test**: Existing unit test explicitly constructs `DecisionConfig(monitor_authority="decide_undetermined")` rather than testing unconfigured defaults. | Changes to default `DecisionConfig` parameters would not trigger regression failure. | Add test asserting `DecisionConfig()` default behavior on undetermined benign verdicts. | **Open** |
| **TEST-03** | Testing | **Medium** | `tests/integration/` | `test_firewall_core.py` | **Absence of Review Stale-State Integration Tests**: No test verifies behavior when session state changes between ticket creation and approval. | Fails to detect SEC-01 and SEC-03 vulnerabilities. | Add adversarial integration test modifying state during review lifecycle. | **Open** |
| **TEST-04** | Testing | **Medium** | `tests/invariants/` | `test_security_invariants_state.py` | **Single-Threaded State Testing**: Invariant tests do not test concurrent event submission across sessions. | Race conditions in session locking or token generation remain unverified. | Add multi-threaded concurrency stress test (`concurrent.futures`). | **Open** |
| **TEST-05** | Testing | **Low** | `tests/golden/` | `contracts_schema_snapshot.json` | **Static Schema Snapshot Requires Manual Sync**: Golden snapshot requires manual regeneration upon schema changes. | Developer friction when extending domain models. | Automate snapshot validation and regeneration flags in test runner. | **Open** |

---

### 2.5 Documentation & Research Defects (DOC)

| ID | Category | Severity | File Path | Location | Finding | Impact | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|---|
| **DOC-01** | Documentation | **High** | `RESEARCH_PAPER/` | `SHRISTI_RP.md`, `AKSHAT_RP.md` | **Unqualified Research Claims in Student Manuscripts**: Manuscripts describe benchmark evaluations without disclosing that the empirical scripts bypassed `FirewallCore`. | Misleading presentation of project maturity and integration in academic submissions. | Add clear disclosures explaining that Ollama scripts were exploratory pilots and that core integration is ongoing. | **Open** |
| **DOC-02** | Documentation | **Medium** | `docs/PROJECT_AUDIT.md` | §1 & §2 | **Stale Audit Report Status**: `PROJECT_AUDIT.md` (dated Oct 29, 2026) lists `core.py`, `decision/`, `executor/`, `policy/` as 0% complete, whereas they are now fully built. | Creates confusion regarding current codebase completion. | Update `PROJECT_AUDIT.md` to reflect post-commit `cb208f9` status. | **Open** |
| **DOC-03** | Documentation | **Medium** | `README.md` | Line 1 | **Empty Project README**: `README.md` contains only `# ai-agent-permission-firewall`. | No installation instructions, quickstart guide, or architecture overview for evaluators. | Author comprehensive README with setup, architecture, and testing instructions. | **Open** |
| **DOC-04** | Documentation | **Low** | `docs/04_PRD.md` | §Requirements | **Discrepancy in Invariant Numbering**: Some older docs refer to INV-01..INV-06, while newer docs define INV-01..INV-12. | Inconsistent cross-referencing in technical specifications. | Standardize all documents on canonical INV-01 through INV-12 from `01_THREAT_MODEL.md`. | **Open** |
| **DOC-05** | Documentation | **Low** | `docs/rules.md` | Component ownership | **Ownership Ambiguity on Decision Combinator**: `rules.md` lists `decision/` under Karishma & Akshat without clear arbitration mechanism. | Potential coordination friction during policy changes. | Designate primary authority for combinator branches (e.g. Karishma for D2/D3, Akshat for D1/D4/D5). | **Open** |
| **DOC-06** | Documentation | **Informational**| `.env.example` | File root | **Empty 0-Byte Example Environment File**: `.env.example` has 0 bytes. | Users do not know required environment variables (e.g. HMAC keys, model endpoints). | Document standard environment variables in `.env.example`. | **Open** |

---
*End of Defect Register.*


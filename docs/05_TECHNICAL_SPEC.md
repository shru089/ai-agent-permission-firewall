# 05 — Technical Specification

> **Everything in this document is PROPOSED and unimplemented.** Schemas, endpoints, file formats and module names are designs for the team to approve (`09`), not descriptions of existing code. Terminology: `00` §2. Formal semantics: `03`. Requirements: `04`. Invariants: `01` §8.

---

## 1. Stack (challenged and adjusted)

| Choice | Decision | Note |
|---|---|---|
| Python 3.11+ | Keep | |
| Pydantic v2 | Keep | Single source of truth for contracts; export JSON Schema. |
| FastAPI | **Keep, but as a thin adapter** over an in-process `FirewallCore` library | Experiments call the core directly: no HTTP noise in latency, easier determinism (`D-16`). |
| SQLite (WAL mode) | Keep | Single-writer, single-process (`A-07`). Labels in a **separate** SQLite file. PostgreSQL deferred. |
| pytest + Hypothesis | Keep pytest; **add Hypothesis** | Property tests are the natural tool for policy semantics and decision-function properties. |
| ruff + mypy | Add | Cheap guard against contract drift. |
| Redis, brokers, extra services | **Not used** | No requirement justifies them (`NFR-03`). |
| LLM access | Behind a `ModelClient` interface (local or hosted) | CI uses recorded responses; no network in unit tests. |

---

## 2. Repository structure

```
agent-permission-firewall/
├─ docs/                       # the ten documents (00–09)
├─ pyproject.toml              # pinned dependencies; ruff/mypy/pytest config
├─ CODEOWNERS                  # contracts/ requires all four owners
├─ config/
│  ├─ firewall.yaml            # κ: monitor_authority, mandatory_review_classes, suspicious_map, timeouts
│  ├─ registry.yaml            # tools, resources, destinations
│  ├─ policy_stateless.yaml    # rules using only action args and registry facts
│  ├─ policy_stateful.yaml     # adds rules over session state
│  └─ arms/                    # B0.yaml … B6.yaml, P1.yaml (one manifest per arm)
├─ src/fw/
│  ├─ contracts/               # Pydantic models, enums, canonical hashing, versions  (SHARED)
│  ├─ core.py                  # FirewallCore.submit(request) — orchestrator (C1)
│  ├─ gateway/                 # validation, auth, id assignment, per-session lock (C1)
│  ├─ state/                   # event model, fold Φ, views (C2)
│  ├─ policy/                  # rule loader, three-valued evaluator (C3); registry loader (C9)
│  ├─ monitors/                # base.py, trivial.py, action_only.py, transcript.py, hybrid.py, model_client.py (C4)
│  ├─ decision/                # pure decision function (C5)
│  ├─ executor/                # token store, hash/head checks, tool dispatch (C6)
│  ├─ review/                  # ticket store, resolution, expiry (C8)
│  ├─ audit/                   # hash-chained store, JSONL export, verification (C7)
│  ├─ tools_sim/               # deterministic simulated tools (C10)
│  ├─ api/                     # FastAPI adapter (thin)
│  └─ experiments/             # generator/, oracle/, runner.py, metrics.py, stats.py (C11)
├─ labels/                     # sealed label store builder; not importable from fw.core (INV-08)
├─ data/                       # generated scenario specs (no labels); dev/ calib/ test/ (test hash-committed)
├─ runs/                       # run manifests and outputs
└─ tests/
   ├─ unit/  ├─ property/  ├─ integration/  ├─ invariants/  └─ experiments/
```

**Import rules (checked by test `T-EXP-009` / `T-INV-08`):** `fw.core`, `fw.monitors`, `fw.policy` must not import `labels/` or `fw.experiments.oracle`. `fw.policy` must not be imported by `fw.experiments.oracle`.

---

## 3. Contracts (`src/fw/contracts/`)

All modules use these models; none defines its own. Version constant `CONTRACTS_VERSION = "0.1.0"` (semantic versioning; breaking change ⇒ major).

### 3.1 Enumerations

```python
class Decision(str, Enum):        ALLOW="ALLOW"; DENY="DENY"; REVIEW="REVIEW"
class PolicyVerdict(str, Enum):   PROHIBIT="PROHIBIT"; PERMIT="PERMIT"; UNDETERMINED="UNDETERMINED"; EVIDENCE_MISSING="EVIDENCE_MISSING"
class MonitorVerdict(str, Enum):  BENIGN="BENIGN"; SUSPICIOUS="SUSPICIOUS"; UNKNOWN="UNKNOWN"; NOT_CONSULTED="NOT_CONSULTED"
class ScoreKind(str, Enum):       NONE; HEURISTIC_RISK; MODEL_PROBABILITY_UNCALIBRATED; MODEL_PROBABILITY_CALIBRATED; MODEL_VERBALIZED_CONFIDENCE
class ToolClass(str, Enum):       READ_LOW; READ_SENSITIVE; WRITE_INTERNAL; EGRESS_EXTERNAL; DESTRUCTIVE; PRIVILEGED_ADMIN
class Classification(str, Enum):  PUBLIC; INTERNAL; CONFIDENTIAL; UNKNOWN
class Zone(str, Enum):            INTERNAL; EXTERNAL; UNKNOWN
class Provenance(str, Enum):      GATEWAY; REGISTRY; TOOL_TYPED; TOOL_FREETEXT; AGENT_CLAIM
class ExecStatus(str, Enum):      EXECUTED; FAILED; EXEC_UNKNOWN; NOT_EXECUTED
```

`Provenance` values `TOOL_FREETEXT` and `AGENT_CLAIM` are **never** read by `Φ` for security-relevant fields (`INV-07`).

### 3.2 Core models (abridged)

```python
class ActionRequest(BaseModel):                      # from the agent (untrusted)
    schema_version: str                              # contracts version
    session_id: str
    tool: str
    arguments: dict[str, JSONScalarOrList]           # validated per tool schema in the registry
    declared_intent: str | None = None               # logged only; never used for decisions or reviewer summaries
    model_config = ConfigDict(extra="forbid")

class CanonicalAction(BaseModel):                    # server-assigned
    action_id: str                                   # UUID
    session_id: str
    seq: int                                         # monotonic per session, assigned by gateway
    tool: str
    arguments: dict
    action_hash: str                                 # SHA-256, see §4

class Event(BaseModel):                              # one element of H_t
    event_id: str; session_id: str; seq: int
    type: Literal["ACTION_RECEIVED","ACTION_DENIED","EXECUTED","FAILED","EXEC_UNKNOWN","REVIEW_RESOLVED"]
    action_id: str
    fields: dict[str, TaggedValue]                   # TaggedValue = {value, provenance}
    free_text: str | None                            # tool-returned text; provenance TOOL_FREETEXT
    decision: Decision | None

class SessionState(BaseModel):                       # S_t (data-export domain)
    state_version: str
    head_hash: str
    bound_resource: ResourceRef | None               # implicit binding mode
    selected_resources: list[ResourceRef]            # each: ref, classification (REGISTRY), selected_seq
    jobs: dict[str, ExportJob]                       # job_id → resource_refs, destination_ref, zone, created_seq
    destination: DestinationRef | None               # implicit binding mode
    job_created: bool
    egress_counters: dict[Zone, EgressCounter]       # rows/bytes executed per zone
    anomalies: list[Anomaly]                         # CONFLICTING_SELECTION, UNKNOWN_CLASSIFICATION, …

class PolicyResult(BaseModel):
    verdict: PolicyVerdict
    matched_rules: list[str]; maybe_rules: list[str]
    missing_fields: list[str]
    policy_hash: str; registry_hash: str

class MonitorView(BaseModel):                        # allow-listed projection π_m — see §8
    monitor_id: str
    action: CanonicalAction
    registry_facts: dict                             # facts about entities named in the action only
    goal: dict | None
    policy_text: str | None
    transcript: str | None                           # only for TranscriptMonitor
    state_summary: dict | None                       # only for HybridMonitor (typed fields + event refs)
    # NO label fields, no future actions, no scenario metadata, by construction

class MonitorAssessment(BaseModel):
    verdict: MonitorVerdict
    score: float | None = None
    score_kind: ScoreKind = ScoreKind.NONE
    rationale: str | None                            # free text, logged only
    raw_output: str | None                           # stored separately from parsed verdict
    model_id: str | None; prompt_hash: str | None; monitor_version: str
    latency_ms: float; error: str | None = None

class DecisionRecord(BaseModel):
    decision_id: str; action_id: str; action_hash: str; state_head_hash: str
    decision: Decision; reason_codes: list[str]; evidence_refs: list[str]
    policy_verdict: PolicyVerdict; monitor_verdict: MonitorVerdict
    versions: VersionSet                             # contracts, policy_hash, registry_hash, monitor_version, prompt_hash, firewall_config_hash
    timings_ms: dict[str, float]                     # validate, state_view, policy, monitor, decide, audit_write, total

class AuthorizationToken(BaseModel):
    token_id: str; action_id: str; action_hash: str; state_head_hash: str
    decision_id: str; nonce: str; expires_at_ms: int
    # single-use flag lives in the DB, flipped atomically by the executor

class ReviewTicket(BaseModel):
    ticket_id: str; action_id: str; action_hash: str; created_ms: int; expires_ms: int
    status: Literal["PENDING","APPROVED","REJECTED","EXPIRED","EXECUTED","STALE"]
    summary: ReviewerView                            # gateway-generated from typed fields only
    resolved_by: str | None; resolved_ms: int | None
```

---

## 4. Canonical hashing

```
canonical_json(x): UTF-8, keys sorted, no insignificant whitespace, integers as integers,
                   floats rejected in arguments (use strings/ints), Unicode NFC normalized.
action_hash = SHA-256( canonical_json({"v": CONTRACTS_VERSION, "session_id": …, "seq": …, "tool": …, "args": …}) )
```

Including `session_id` and `seq` makes two identical calls hash differently, which supports single-use authorization (`INV-06`). Test `T-GW-006` checks stability under key order/whitespace/Unicode forms.

### State-head hashing (PROPOSED — D-36)

```
genesis_head = SHA-256( "GENESIS:" || Unicode_NFC(session_id) )
head_hash_t  = SHA-256( prior_head_bytes || canonical_json(event_data, reject_floats=False) )
```

where `prior_head_bytes = prior_head.encode("utf-8")` (64 ASCII hex bytes), and `event_data` for a `StateEventEnvelope` is canonically serialized as:
```json
{
  "action_id": "act_0001",
  "event_type": "EXECUTED",
  "payload": { "arguments": { ... }, "tool": "..." },
  "prior_head": "800112320e...",
  "seq": 1,
  "session_id": "sess_001",
  "token_id": "tok_0001"
}
```

This binds monotonic sequence, prior state head, action ID, authorization token, and execution payload into an append-only hash chain (`INV-09`, `INV-12`).

---

## 5. API endpoints (PROPOSED)

Headers: `X-Agent-Key` (agent), `X-Reviewer-Key` (reviewer). Bodies are JSON.

| Method & path | Purpose |
|---|---|
| `POST /v1/sessions` | Create a session → `{session_id}` |
| `POST /v1/sessions/{sid}/actions` | Submit an `ActionRequest` → decision and (if executed) result |
| `GET /v1/actions/{action_id}` | Status of an action (e.g. poll a pending review) |
| `GET /v1/reviews?status=PENDING` | List tickets (reviewer) |
| `POST /v1/reviews/{ticket_id}/resolve` | Approve or reject (reviewer) |
| `GET /v1/sessions/{sid}/audit` | Audit records for a session |
| `GET /v1/audit/verify` | Verify the hash chain |
| `GET /v1/config` | Versions and hashes (contracts, policy, registry, monitor) |
| `GET /healthz` | Liveness |

**Submit — request**
```json
POST /v1/sessions/7c1e…/actions
{ "schema_version": "0.1.0", "session_id": "7c1e…", "tool": "execute_export", "arguments": {} }
```

**Submit — responses (examples)**
```json
{ "action_id": "a-0004", "status": "DENIED", "decision": "DENY",
  "reason_codes": ["POLICY_PROHIBIT:R1-no-confidential-external-export"],
  "policy_verdict": "PROHIBIT" }
```
```json
{ "action_id": "a-0004", "status": "PENDING_REVIEW", "decision": "REVIEW",
  "reason_codes": ["EVIDENCE_MISSING:bound_resource.classification"], "ticket_id": "t-0017" }
```
```json
{ "action_id": "a-0002", "status": "EXECUTED", "decision": "ALLOW",
  "reason_codes": ["POLICY_PERMIT:P-filler-read-low"],
  "result": { "typed": { "rows_checked": 1200 }, "text": "Schema valid." } }
```
Other statuses: `BUSY`, `FAILED`, `EXEC_UNKNOWN`.

**Resolve review — request**
```json
POST /v1/reviews/t-0017/resolve
{ "outcome": "APPROVE" | "REJECT", "reviewer_id": "rev-1", "comment": "…" }
```

HTTP codes: `200` decisions of any kind (the decision is in the body), `400` malformed JSON, `401` auth, `409` `BUSY`, `404` unknown id.

---

## 6. Data model (SQLite; PROPOSED)

One **append-only audit table** is the single source of truth; other tables are indexes or mutable control state.

| Table | Purpose | Mutable? |
|---|---|---|
| `audit_records(rec_id PK, session_id, seq, type, payload_json, prev_hash, hash, mono_ns)` | All events, decisions, monitor runs, executions, review resolutions. `hash = SHA-256(prev_hash ‖ canonical_json(payload))`. | No (insert only; no update/delete code path) |
| `sessions(session_id PK, agent_id, created_ms, in_flight_action_id NULL)` | Session control and per-session lock | Yes |
| `actions(action_id PK, session_id, seq, tool, args_json, action_hash)` | Canonical actions | No |
| `tokens(token_id PK, action_id, action_hash, state_head_hash, nonce, expires_ms, used INTEGER)` | Authorization tokens; `used` flipped 0→1 atomically | `used` only |
| `review_tickets(ticket_id PK, action_id, action_hash, status, created_ms, expires_ms, resolved_by, resolved_ms)` | Review state | Yes |
| `config_versions(config_hash PK, contracts_version, policy_hash, registry_hash, monitor_version, prompt_hash, created_ms)` | What was active | No |
| `experiment_runs(run_id PK, manifest_json, started_ms, ended_ms)` | Run metadata | No |
| `scenarios(scenario_id PK, family, template_id, split, spec_json)` | Scenario specs **without labels** | No |
| **`labels.sqlite` (separate file)** `labels(scenario_id, step, y, critical_index, oracle_version)` | Ground truth | Written once at generation; read only by `fw.experiments.metrics` after a run |

Pragmas: `journal_mode=WAL`, `foreign_keys=ON`, `synchronous=FULL` for the audit file.

---

## 7. Policy and registry formats and semantics (PROPOSED)

### 7.1 Registry (`config/registry.yaml`, read-only at runtime)

```yaml
registry_version: "0.1.0"
tools:
  select_resource:       { class: READ_SENSITIVE, args: { resource_ref: string } }
  create_export_job:     { class: WRITE_INTERNAL, args: {} }            # implicit binding
  configure_destination: { class: WRITE_INTERNAL, args: { destination_ref: string } }
  execute_export:        { class: EGRESS_EXTERNAL, args: {} }
  validate_schema:       { class: READ_LOW, args: {} }
  relabel_resource:      { class: PRIVILEGED_ADMIN, args: { resource_ref: string, classification: string } }
resources:
  customer_records:   { classification: CONFIDENTIAL, rows: 5000 }
  public_records:     { classification: PUBLIC,       rows: 800 }
destinations:
  external_storage:   { zone: EXTERNAL }
  internal_archive:   { zone: INTERNAL }
  backup_bucket:      { zone: EXTERNAL }          # alias test (ATK-08)
```

### 7.2 Policy (`config/policy_stateful.yaml`)

```yaml
policy_version: "0.1.0"
binding_mode: implicit            # implicit | explicit
rules:
  - id: R1-no-confidential-external-export
    effect: PROHIBIT
    tool: execute_export
    when:
      - { state: bound_resource.classification, op: eq, value: CONFIDENTIAL }
      - { state: destination.zone,             op: eq, value: EXTERNAL }
  - id: R2-permit-public-external-export
    effect: PERMIT
    tool: execute_export
    when:
      - { state: bound_resource.classification, op: eq, value: PUBLIC }
      - { state: destination.zone,             op: eq, value: EXTERNAL }
      - { state: job_created,                  op: eq, value: true }
  - id: R3-permit-internal-export
    effect: PERMIT
    tool: execute_export
    when:
      - { state: destination.zone, op: eq, value: INTERNAL }
  - id: P-filler-read-low
    effect: PERMIT
    tool_class: READ_LOW
  - id: R4-agents-cannot-relabel
    effect: PROHIBIT
    tool: relabel_resource
  - id: R5-cumulative-external-egress-limit
    effect: PROHIBIT
    tool: execute_export
    when:
      - { state: egress_counters.EXTERNAL.rows_plus_pending, op: gt, value: 1000 }   # placeholder value
```
(`value: 1000` is an illustrative placeholder, not a recommendation.)

**Condition sources:** `state:` (path into `S_t`), `arg:` (an argument of the action), `registry:` (fact about a named entity, e.g. `registry.destination(arg.destination_ref).zone`).  
**Operators:** `eq, neq, in, gt, lt, exists`.  
**Unknown handling:** a path that is absent, `null`, or `UNKNOWN` makes the condition `UNKNOWN` (never `FALSE`).  
**Evaluation:** exactly `03` §3. The stateless policy file contains only `arg:`/`registry:` conditions.

### 7.3 Decision configuration (`config/firewall.yaml`)

```yaml
monitor_authority: decide_undetermined     # none | decide_undetermined | escalate_only
mandatory_review_classes: [DESTRUCTIVE, PRIVILEGED_ADMIN]   # MR in 03 §4. EXPERIMENT-ARM value, identical for all arms (D-13).
                                                            # A production-style config adds EGRESS_EXTERNAL; ablation A-06 tests that.
suspicious_map: REVIEW                     # REVIEW | DENY
monitor_timeout_ms: null                   # set after baseline latency measurement (OQ-14)
review_expiry_s: null                      # set per experiment
```

**Security Invariants Enforced by Core:**
1. **Advisory-Only Monitor / Rejection Cascade:** Semantic monitors and the rejection cascade are strictly advisory. The adapter and monitor never independently authorize (`ALLOW`), execute, or deny actions. The core firewall makes all final decisions.
2. **PROHIBIT Dominance:** `PROHIBIT` always wins. Deterministic policy evaluations of `PROHIBIT` always map to `DENY` regardless of monitor advisory output (`BENIGN`, `SUSPICIOUS`, `UNKNOWN`, timeout, malformed JSON, or exception).
3. **Escalation of Uncertainty:** Policy uncertainty must escalate. `UNDETERMINED + BENIGN` produces `REVIEW` (`UNDETERMINED_BENIGN_REQUIRES_REVIEW`), never `ALLOW`.
4. **Mandatory Review:** Tools belonging to `mandatory_review_classes` always escalate to `REVIEW` even if the monitor advisory is `BENIGN` / `LOW_RISK`.

---

## 8. State tracking and views

### 8.1 Tool effects on `S_t` (data-export domain)

| Tool (class) | Effect on state when executed | Anomalies |
|---|---|---|
| `select_resource(ref)` (READ_SENSITIVE) | Look up classification in registry; append to `selected_resources`; implicit mode: set `bound_resource`. | If a different resource is already bound and no `reset_context` since ⇒ `CONFLICTING_SELECTION`. Unknown ref ⇒ `UNKNOWN_CLASSIFICATION`. |
| `reset_context()` (WRITE_INTERNAL) | Clear `bound_resource`, `destination`, `job_created`. | — |
| `create_export_job()` (WRITE_INTERNAL) | `job_created = true` (implicit). Explicit mode: `create_export_job(resource_ref, destination_ref)` creates `jobs[job_id]` with registry zone. | — |
| `configure_destination(ref)` (WRITE_INTERNAL) | Set `destination = {ref, zone from registry}`. | Unknown ref ⇒ zone `UNKNOWN`. |
| `execute_export()` / `execute_export(job_id)` (EGRESS_EXTERNAL) | After authorization and execution: add rows to `egress_counters[zone]`. | — |
| `read_resource(ref)` (READ_SENSITIVE) | None (read-only, internal). | — |
| `relabel_resource(...)` (PRIVILEGED_ADMIN) | Not executable by agents (R4). | — |
| `validate_schema()`, `check_disk_space()`, `ping_database()` (READ_LOW) | None. Output text stored as `TOOL_FREETEXT`. | — |
| `copy_resource(src,dst)` *(stretch)* | `dst` inherits `src` classification (label propagation). | — |

Denied or rejected actions append `ACTION_DENIED` and do not change security-relevant state.

### 8.2 Information views (allow-lists) and isolation

| View | Fields |
|---|---|
| `PolicyView` | `CanonicalAction`, `SessionState`, registry snapshot |
| `MonitorView[ActionOnly]` | action, registry facts of entities *named in* the action, goal, policy text |
| `MonitorView[Transcript]` | as above + `transcript` (text serialization of `H_t`, including free text, as in [P1]) |
| `MonitorView[Hybrid]` | action, registry facts, goal, policy text, `state_summary` (typed fields) + event refs |
| `ReviewerView` | gateway-generated: tool, typed arguments, policy verdict, reason codes, state facts, monitor assessment labeled *advisory*; **never** `declared_intent` as fact |

**MonitorView Isolation and Sanitization Guarantees:**
- **Defensive Deep Copying:** All projections created for `MonitorView` (action, state summary, history, registry facts) are deep-copied. Any modification attempted by a monitor or cascade stage cannot mutate the core firewall's state or action objects.
- **Sensitive Field Sanitization:** Sensitive internal fields—including authorization tokens, session keys, passwords, API keys, private keys, and secrets—are redacted or stripped from monitor views and transcripts before evaluation. Semantic monitors are never exposed to internal credentials or tokens.

---

## 9. Monitor interface

```python
class Monitor(Protocol):
    monitor_id: str
    version: str
    def assess(self, view: MonitorView, *, timeout_ms: int | None) -> MonitorAssessment: ...
```

Rules:

1. `assess` must never raise to the core: exceptions, timeouts and parse failures are converted to `MonitorAssessment(verdict=UNKNOWN, error=...)` by the wrapper.
2. LLM monitors request strict JSON (`{"verdict": "BENIGN"|"SUSPICIOUS", "rationale": str}`); the parser must be exact-match (no "last token wins" fallback); anything else ⇒ `UNKNOWN`. The raw string is stored in `raw_output` (cf. [P3] §IV.F).
3. Temperature 0 and pinned model identifier; prompt text is hashed and stored.
4. `Transcript` and `Hybrid` monitors build their prompts only from the `MonitorView` fields.
5. Mapping from [P3]-style tiers: `PASS → BENIGN`, `FAIL → SUSPICIOUS`, `UNSURE → UNKNOWN`.
6. Scores follow `03` §5; `MODEL_VERBALIZED_CONFIDENCE` is stored but a type guard prevents its use in `Δ`.
7. **Advisory Semantics in Adapter:** The cascade adapter converts monitor assessments into advisory verdicts: `BENIGN → LOW_RISK`, `SUSPICIOUS → ELEVATED_RISK`, `UNKNOWN → UNCERTAIN`, and errors/timeouts → `UNAVAILABLE`. The adapter returns `MonitorAdvisory` with `decision = None` and never directly maps to `ALLOW` or `DENY`.
8. **Review Approval Revalidation (`INV-05`):** When a human approver resolves a ticket via `resolve_review()`, the firewall revalidates against current authoritative state and policy:
   - Verifies state freshness (`recorded_state_head == state.head_hash`); if state has diverged, approval fails closed to `DENY` (`STALE_DECISION`).
   - Re-evaluates deterministic policy; if policy now returns `PROHIBIT`, execution is denied (`POLICY_PROHIBIT`).
   - Execution tokens are only minted when state and policy remain valid.

---

## 10. Error handling

| Code | When | Decision |
|---|---|---|
| `SCHEMA_INVALID` | Validation failure | DENY |
| `AUTH_FAILED` | Bad key | DENY |
| `UNKNOWN_TOOL` | Tool not in registry | DENY |
| `BUSY` | Another action in flight or review pending | not decided; client retries |
| `STATE_UNAVAILABLE` | Fold error, chain mismatch | DENY |
| `POLICY_ERROR` | Rule evaluation exception | DENY |
| `AUDIT_UNAVAILABLE` | Audit insert failed | DENY (nothing executes) |
| `MONITOR_UNAVAILABLE` | Timeout/error/unparseable | REVIEW (via `UNKNOWN`) |
| `EVIDENCE_MISSING:<fields>` | `EVIDENCE_MISSING` verdict | REVIEW |
| `STALE_DECISION` | State head changed before execution | re-run pipeline once, else DENY |
| `HASH_MISMATCH` / `TOKEN_REUSED` / `TOKEN_EXPIRED` | Executor checks | refuse; audit |
| `REVIEW_EXPIRED` / `REVIEW_REJECTED` | Ticket outcome | DENY-equivalent |

No error path ever returns `ALLOW`.

---

## 11. Logging and audit format

Every audit record is a JSON object (one per line in exports):

```json
{
  "rec_id": 412, "session_id": "7c1e…", "seq": 4, "type": "DECISION",
  "payload": {
    "action_id": "a-0004", "action_hash": "9f2c…", "state_head_hash": "31ab…",
    "decision": "DENY", "reason_codes": ["POLICY_PROHIBIT:R1-no-confidential-external-export"],
    "policy_verdict": "PROHIBIT", "monitor_verdict": "NOT_CONSULTED",
    "evidence_refs": ["ev-0001", "ev-0003"],
    "versions": { "contracts": "0.1.0", "policy_hash": "…", "registry_hash": "…", "monitor_version": "none", "prompt_hash": null, "firewall_config_hash": "…" },
    "timings_ms": { "validate": 0.1, "state_view": 0.2, "policy": 0.1, "monitor": 0.0, "decide": 0.0, "audit_write": 0.6, "total": 1.2 }
  },
  "prev_hash": "c4d1…", "hash": "7be0…", "mono_ns": 1234567890123
}
```

Record types: `ACTION_RECEIVED`, `POLICY_EVAL`, `MONITOR_RUN`, `DECISION`, `TOKEN_ISSUED`, `EXECUTION`, `REVIEW_CREATED`, `REVIEW_RESOLVED`, `ERROR`. Secrets are never logged. Labels are never logged.

---

## 12. Configuration and versioning

- **Contracts:** semantic version in `contracts/__init__.py`; a golden JSON-Schema snapshot test fails on any model change; changing `contracts/` requires approval from all four owners (`CODEOWNERS`).
- **Policy, registry, firewall config, prompts:** content-hashed (SHA-256 of canonical bytes); hashes written to `config_versions` and every `DecisionRecord`.
- **Arm manifests** (`config/arms/*.yaml`) fully specify an arm: policy file, `monitor_authority`, `MR`, `suspicious_map`, monitor id and version, model id, prompt file, decoding settings, timeouts.
- **Run manifest** (`runs/<run_id>/manifest.json`): all arm manifests, scenario split hashes, seeds, git commit, dependency lock hash, hardware/OS, model host/version, start/end times.

---

## 13. Testing requirements

pytest markers: `unit`, `property`, `integration`, `invariant`, `experiment`. CI blocks merges on failing `invariant` tests. No network in CI: LLM calls use recorded fixtures.

| ID | Test |
|---|---|
| T-GW-001 | Schema validation rejects malformed/extra-field/oversized requests (Hypothesis). |
| T-GW-002 | Gateway ignores agent-supplied ids, hashes and sequence numbers. |
| T-GW-003 | Missing/invalid key ⇒ `DENY AUTH_FAILED`. |
| T-GW-004 | Concurrent submission ⇒ `BUSY`; pending review blocks session. |
| T-GW-005 | Unknown tool ⇒ `DENY UNKNOWN_TOOL`. |
| T-GW-006 | Canonical hash stable under key order, whitespace, Unicode normalization. |
| T-STA-001 | `Φ` deterministic; replay of audit log reproduces state. |
| T-STA-002 | Free text and agent claims never enter `S_t` security fields (forged-classification fixtures). |
| T-STA-003 | Selection, binding, conflict and unknown-classification anomalies. |
| T-STA-004 | Cumulative egress counters across steps. |
| T-STA-005 | Views contain only allow-listed fields; canary tokens never appear. |
| T-STA-006 | Implicit and explicit binding modes. |
| T-POL-001 | Three-valued truth tables for every operator. |
| T-POL-002 | PROHIBIT dominates PERMIT (property). |
| T-POL-003 | Evidence monotonicity (property). |
| T-POL-004 | Rule-order independence (property). |
| T-POL-005 | Full coverage of [P1]-style cases: all (classification × zone × setup-completeness) combinations, plus H01–H12-equivalent fixtures expressed in the typed domain. |
| T-POL-006 | Policy/registry load, hash recording, refusal on invalid files. |
| T-POL-007 | Reason codes and rule ids present. |
| T-MON-001 | Monitor conformance suite (interface, never raises). |
| T-MON-002 | Trivial monitors behave as specified. |
| T-MON-003 | Timeout ⇒ `UNKNOWN`. |
| T-MON-004 | Malformed output ⇒ `UNKNOWN`; exact-match parser. |
| T-MON-005 | Raw, parsed and final decision stored separately. |
| T-MON-006 | `score_kind` declared; verbalized confidence cannot influence `Δ`. |
| T-MON-007 | Monitor-view leakage canary. |
| T-DEC-001 | Exhaustive truth table for `Δ` + properties P-PROHIB, P-FAILCLOSED, P-MONO, P-NOLEAK. |
| T-DEC-002 | Reason codes and evidence refs populated. |
| T-DEC-003 | Config switches (`monitor_authority`, `MR`, `suspicious_map`) behave per `03` §4. |
| T-EXE-001 | Altered arguments ⇒ hash mismatch ⇒ refused. |
| T-EXE-002 | Token reuse refused. |
| T-EXE-003 | State head change ⇒ `STALE_DECISION`. |
| T-EXE-004 | Success/failure recorded as typed event; no retry. |
| T-EXE-005 | Crash injection ⇒ `EXEC_UNKNOWN`, no re-execution. |
| T-AUD-001 | Hash chain verifies; tamper/delete detected. |
| T-AUD-002 | Versions and timings present in every decision record. |
| T-AUD-003 | Label store unreachable from runtime code (import-graph + file permission). |
| T-AUD-004 | JSONL export schema. |
| T-REV-001 | REVIEW creates PENDING ticket; zero executions. |
| T-REV-002 | Authenticated APPROVE executes exactly once. |
| T-REV-003 | Expiry ⇒ DENY-equivalent. |
| T-REV-004 | Reviewer summary built from typed fields only. |
| T-REV-005 | Approval of a different action/hash refused. |
| T-EXP-001 | Generator determinism (byte-identical for equal seeds). |
| T-EXP-002 | Action D invariance for every history-dependent pair. |
| T-EXP-003 | Manifest completeness. |
| T-EXP-004 | Metrics fixtures reproduce [P1] Table I and [P3] Table III from reported counts; undefined cases return `NA`. |
| T-EXP-005 | Split disjointness by template family; test-set hash commitment verified. |
| T-EXP-006 | Statistics scripts against known examples (Wilson, zero-event bound `1−0.05^{1/250}≈1.19%`, `n≥59`/`299`). |
| T-EXP-007 | Trivial baselines yield `03` §8.4 rows. |
| T-EXP-008 | TF and OL mode fixtures. |
| T-EXP-009 | Label oracle independent of policy engine (import-graph). |
| T-API-001…003 | Adapter contract tests: submit, review resolve, audit verify. |
| T-NFR-001 | Deterministic rerun: two runs of a deterministic arm give identical decision logs (modulo timestamps). |
| T-NFR-002 | Stage timings present in 100% of decision records. |
| T-NFR-003 | Documented setup runs clean in a fresh environment. |
| **T-INV-01** | No tool execution without matching decision: instrument tools; fuzz sequences incl. direct-call attempts; zero unauthorized executions. |
| **T-INV-02** | Modify args/state between decision and execution ⇒ refused. |
| **T-INV-03** | For all monitor outputs and review outcomes, a `PROHIBIT` verdict ends in DENY (exhaustive). |
| **T-INV-04** | Inject faults in every component; no ALLOW results. |
| **T-INV-05** | REVIEW with no approval ⇒ zero executions; expiry ⇒ deny. |
| **T-INV-06** | Replay of token/approval refused. |
| **T-INV-07** | Spoofed text cannot change `S_t`; policy verdict unchanged. |
| **T-INV-08** | Canary labels never reach monitor prompts, audit log or views; import-graph check. |
| **T-INV-09** | Chain verification and write-failure ⇒ no execution. |
| **T-INV-10** | 100% of decision records carry all version fields. |
| **T-INV-11** | Exhaustive monotone-strictness check of `Δ`. |
| **T-INV-12** | Replay determinism for ≥ N recorded sessions (N set in Phase 4 exit). |

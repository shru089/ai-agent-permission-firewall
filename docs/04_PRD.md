# 04 — Product Requirements Document (MVP)

**Status:** `PROPOSED`. Requirement IDs are stable: do not renumber; deprecate instead. Terminology: `00` §2. Threat model and invariants: `01`. Architecture: `02`. Formal model: `03`. Technical details: `05`. Test IDs are defined in `05` §13 and traced in `07`. Phases refer to `08`.

---

## 1. Problem statement

Autonomous agents call tools that read, change and send data. When an agent is misled by injected content or simply misaligned, it can cause unauthorized effects — including effects that only emerge from a *sequence* of individually harmless calls (e.g. select a confidential dataset, set an external destination, then export). Per-call checks and text-reading model monitors have not been shown to handle this reliably ([P1] reports one such failure on a synthetic benchmark), and none of the four reference papers evaluates an end-to-end enforcing system with tested guarantees.

**The product** is a firewall between agent and tools that mediates every call, decides ALLOW / DENY / REVIEW under a versioned policy and an explicit information view, executes only what was authorized, and records everything needed to reproduce and audit decisions. It doubles as the experimental platform for RQ-1 (`00` §5.2).

---

## 2. Users and use cases

| ID | User | Need |
|---|---|---|
| U1 | **Agent integrator** (developer wiring an agent to tools) | Submit tool calls and receive a clear decision; no way to bypass. |
| U2 | **Policy author** | Express prohibitions/permissions, including stateful ones, and test them deterministically. |
| U3 | **Human reviewer** | See a trustworthy summary of what is being asked and approve/reject explicitly. |
| U4 | **Researcher/evaluator** (the team) | Run all arms on identical, labeled scenarios; get reproducible metrics. |
| U5 | **Auditor** | Reconstruct why any action was allowed, denied or escalated. |

| Use case | Description |
|---|---|
| UC-01 | An agent submits an action; firewall returns ALLOW and the executed result. |
| UC-02 | An action violates a hard prohibition (including one that depends on earlier steps); firewall returns DENY with a reason code. |
| UC-03 | An action lacks evidence required by the policy; firewall returns REVIEW; nothing executes until an explicit approval. |
| UC-04 | A reviewer approves/rejects a ticket; only an approval bound to the original action executes it. |
| UC-05 | Policy author changes a rule; tests re-run; new policy version hash appears in decisions. |
| UC-06 | Researcher runs all arms on the development split and reviews error analysis. |
| UC-07 | Researcher freezes configuration and runs the sealed test split once. |
| UC-08 | Auditor replays a session from the audit log and reproduces `S_t` and decisions. |

---

## 3. Goals and non-goals

### Goals

| ID | Goal |
|---|---|
| G-1 | A **functioning firewall** (complete mediation, bound authorization, fail-closed, auditable), not just a classifier (`§6`). |
| G-2 | A deterministic policy engine with stateful rules, as the first and strongest baseline. |
| G-3 | Pluggable monitors with fixed information views so that arms B3–B6 and P1 are comparable (`03` §10). |
| G-4 | A reproducible experiment pipeline with pre-registered primary comparisons. |
| G-5 | A design that a four-person student team can implement without private interpretations of the contracts. |

### Non-goals (MVP)

- Production readiness, real-world tool integrations, performance at scale.
- Composite risk scores (`R` of [P2], CCS of [P4]); embeddings; TRANSFORM; learned policies.
- Workload-aware routing, dynamic thresholds, self-reflection fallback.
- Multi-agent delegation, lineage across arbitrary derivations (stretch family `ATK-09` only).
- Distributed infrastructure, Redis, multiple deployable services, PostgreSQL.
- Any claim of novelty, superiority or publication readiness.

---

## 4. Functional requirements

Priority: **M** = must (MVP), **S** = should (MVP if time allows), **D** = deferred. Phase = roadmap phase (`08`).

### 4.1 Gateway (C1)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-GW-01 | Accept an `ActionRequest` and validate it against the versioned schema. | Malformed/oversized/extra-field requests return `DENY SCHEMA_INVALID` and are audited; property-based tests find no crash. | T-GW-001 | M | 3 |
| FR-GW-02 | Assign `action_id`, per-session monotonic `seq`, and canonical action hash server-side; ignore any agent-supplied values. | Supplying forged ids/hashes has no effect; hash is stable under key-order/whitespace changes. | T-GW-002, T-GW-006 | M | 3 |
| FR-GW-03 | Authenticate the agent/session. | Unauthenticated request ⇒ `DENY AUTH_FAILED`. (MVP: static key per agent.) | T-GW-003 | M | 3 |
| FR-GW-04 | Serialize actions per session; reject concurrent submissions. | Second submission while one is in flight or a review is pending returns `BUSY`. | T-GW-004 | M | 3 |
| FR-GW-05 | Route every supported tool call through the pipeline; unknown tool ⇒ `DENY UNKNOWN_TOOL`. | No tool executes without a gateway decision. | T-GW-005, T-INV-01 | M | 3 |
| FR-GW-06 | Expose the core through a thin FastAPI adapter (the core also runs in-process). | API tests pass; experiment results do not depend on the adapter. | T-API-001..003 | S | 3 |

### 4.2 Evidence & state (C2)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-STA-01 | Compute `S_t` as a pure fold over typed events. | Same events ⇒ identical `S_t`; replaying the audit log reproduces live state for 100% of recorded sessions. | T-STA-001, T-INV-12 | M | 4 |
| FR-STA-02 | Tag every event field with provenance; only `GATEWAY`/`REGISTRY`/`TOOL_TYPED` fields may populate `S_t`. | Forged "Classification: PUBLIC" text in a tool result leaves `S_t` unchanged. | T-STA-002, T-INV-07 | M | 4 |
| FR-STA-03 | Track, at minimum: selected resources with registry classification; export jobs with registry destination zone; cumulative egress counters; anomaly flags (conflicting selection, unknown classification). | State fixtures for each field pass. | T-STA-003, T-STA-004 | M | 4 |
| FR-STA-04 | Support `implicit` and `explicit` binding modes by configuration. | Same scenario set runs under both; differences documented. | T-STA-006 | S | 4 |
| FR-STA-05 | Build per-consumer views by allow-list; no label, future action or test metadata can enter any view. | Canary tokens placed in labels never appear in any view or prompt. | T-STA-005, T-INV-08 | M | 4 |

### 4.3 Policy engine (C3) and registry (C9)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-POL-01 | Evaluate PROHIBIT/PERMIT rules with three-valued logic (`03` §3). | Truth-table tests pass for all combinations. | T-POL-001 | M | 2 |
| FR-POL-02 | Verdict precedence: PROHIBIT ≻ EVIDENCE_MISSING ≻ PERMIT ≻ UNDETERMINED. | Property tests: order independence, prohibit dominance. | T-POL-002, T-POL-004 | M | 2 |
| FR-POL-03 | Missing evidence for a PROHIBIT rule yields `EVIDENCE_MISSING`, not `PERMIT`. | Fixtures reproduce [P1] cases H07/H08 behaviour. | T-POL-003, T-POL-005 | M | 2 |
| FR-POL-04 | Load policy and registry from versioned files; compute content hashes; immutable at runtime. | Invalid files refuse startup; decisions carry the hashes. | T-POL-006, T-INV-10 | M | 2 |
| FR-POL-05 | Every rule has an id; verdicts return matching rule ids and reason codes. | Reason codes appear in decision records. | T-POL-007 | M | 2 |
| FR-POL-06 | Express [P1]'s three export rules (`03` §3 example) and at least: label-downgrade prohibition, destination-zone resolution, cumulative egress limit. | Scenario families `ATK-02/03/06/07/08` evaluated correctly by `B6`. | T-POL-005 | M | 2/6 |
| FR-REG-01 | Registry holds tool schemas and sensitivity classes, resource classifications, destination zones. | Registry hash recorded; agent cannot write to it. | T-POL-006 | M | 2 |

### 4.4 Monitors (C4)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-MON-01 | One monitor interface: `assess(MonitorView) → MonitorAssessment`. | All monitors pass the same conformance suite. | T-MON-001 | M | 6/7 |
| FR-MON-02 | Provide monitors: `AlwaysAllow`, `AlwaysDeny`, `AlwaysReview` (trivial), `ActionOnly`, `Transcript`, `Hybrid`. | Each is selectable by configuration and logs its version. | T-MON-002 | M | 6/7 |
| FR-MON-03 | Each assessment declares `score_kind`; verbalized confidence is never used for decisions. | Decision function ignores scores; type check rejects use of `MODEL_VERBALIZED_CONFIDENCE`. | T-MON-006 | M | 7 |
| FR-MON-04 | Monitor timeout/error/unparseable output ⇒ verdict `UNKNOWN`. | Fault-injection tests. | T-MON-003, T-MON-004 | M | 7 |
| FR-MON-05 | Pin model identifier, prompt hash and decoding settings; store raw output, parsed verdict and final decision separately (cf. [P3] §IV.F). | Audit records contain all three. | T-MON-005 | M | 7 |
| FR-MON-06 | Monitor views contain only allow-listed fields (`03` §10). | Leakage canary test. | T-MON-007 | M | 7 |

### 4.5 Decision function (C5)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-DEC-01 | Implement `03` §4 exactly as a pure function. | Exhaustive enumeration over the finite input domain matches the table. | T-DEC-001 | M | 3 |
| FR-DEC-02 | Return reason codes and evidence references (rule ids, event ids). | Present in every decision record. | T-DEC-002 | M | 3 |
| FR-DEC-03 | Support `monitor_authority`, `MR`, `suspicious_map` configuration. | Ablations `A-05/06/07` run by config only. | T-DEC-003 | M | 3/8 |

### 4.6 Executor (C6)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-EXE-01 | Execute only an action whose hash and state head match the authorization. | Tampered args ⇒ refused. | T-EXE-001, T-INV-02 | M | 3 |
| FR-EXE-02 | Authorization is single-use and expiring. | Replay refused. | T-EXE-002, T-INV-06 | M | 3 |
| FR-EXE-03 | Record outcome (success/failure) as a typed event; no automatic retry. | Failure produces `FAILED` event only. | T-EXE-004 | M | 3 |
| FR-EXE-04 | Crash between token use and outcome ⇒ `EXEC_UNKNOWN`, no re-execution. | Crash-injection test. | T-EXE-005 | S | 3 |

### 4.7 Audit (C7)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-AUD-01 | Append-only, hash-chained records; written before the result returns. | Tamper/deletion detected; write failure ⇒ no execution. | T-AUD-001, T-INV-09 | M | 4 |
| FR-AUD-02 | Record versions (contract, policy, registry, monitor, prompt) and stage timings in every decision. | Fields non-null in 100% of records. | T-AUD-002, T-INV-10 | M | 4 |
| FR-AUD-03 | Keep ground-truth labels in a sealed store separate from the audit log. | No import path from runtime to label store. | T-AUD-003, T-INV-08 | M | 4/5 |
| FR-AUD-04 | Export per-decision JSONL for experiments. | Schema-validated export. | T-AUD-004 | M | 4 |

### 4.8 Review (C8)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-REV-01 | `REVIEW` creates a `PENDING` ticket bound to the action hash; nothing executes. | Execution count = 0 until approval. | T-REV-001, T-INV-05 | M | 3 |
| FR-REV-02 | Authenticated approve/reject; approval bound to hash; single use. | Approval of a different action refused. | T-REV-002, T-REV-005 | M | 3 |
| FR-REV-03 | Expiry ⇒ `EXPIRED` ⇒ treated as DENY. | Timeout test. | T-REV-003 | M | 3 |
| FR-REV-04 | Reviewer summary is gateway-generated; agent-supplied text is never presented as fact. | Summary built from typed fields only. | T-REV-004 | M | 3 |
| FR-REV-05 | Review queue UI, workload-aware routing, reviewer analytics. | — | — | D | 9 |

### 4.9 Experiment platform (C10, C11)

| ID | Requirement | Acceptance criterion | Tests | Pri | Phase |
|---|---|---|---|---|---|
| FR-EXP-01 | Deterministic scenario generator with seeds; families per `06` §3. | Two runs ⇒ byte-identical scenarios. | T-EXP-001 | M | 5/6 |
| FR-EXP-02 | Verify Action D invariance for every history-dependent pair. | Automated check; generation fails on violation. | T-EXP-002 | M | 5 |
| FR-EXP-03 | Runner executes all arms on identical scenarios and writes a run manifest. | Manifest includes seeds, versions, hashes, hardware. | T-EXP-003 | M | 6 |
| FR-EXP-04 | Metrics module implements `03` §8 exactly; fixtures reproduce [P1] Table I and [P3] Table III from their reported counts. | Numeric equality within rounding. | T-EXP-004 | M | 6 |
| FR-EXP-05 | Split by template family/variant; commit test-set hash before tuning. | Disjointness test; hash recorded in repo. | T-EXP-005 | M | 5/6 |
| FR-EXP-06 | Statistics scripts: Wilson, cluster bootstrap, exact McNemar, Holm, zero-event bound. | Validated against known examples. | T-EXP-006 | M | 6/8 |
| FR-EXP-07 | Trivial baselines B0–B2 produce expected rows of `03` §8.4. | Test table. | T-EXP-007 | M | 6 |
| FR-EXP-08 | Support TF and OL modes. | Mode-specific fixtures. | T-EXP-008 | M | 6 |
| FR-EXP-09 | Label oracle is independent of the policy engine. | Import-graph check forbids dependency. | T-EXP-009 | M | 5 |
| FR-DASH-01 | Audit/metrics dashboard. | — | — | D | 9 |

---

## 5. Non-functional requirements

| ID | Requirement | Acceptance criterion | Test |
|---|---|---|---|
| NFR-01 | **Reproducibility:** fixed seeds, pinned dependencies, recorded model ids; reruns of deterministic arms give identical decisions. | Two runs ⇒ identical decision logs (modulo timestamps). | T-NFR-001 |
| NFR-02 | **Timing instrumentation** for every pipeline stage. | Stage timings present in 100% of records. | T-NFR-002 |
| NFR-03 | **Simplicity:** one Python process, SQLite (WAL), no Redis, no message broker. | Architecture review checklist. | — (review) |
| NFR-04 | **Test coverage target (proposed):** ≥ 90% branch coverage on C3, C5, C6; ≥ 80% elsewhere. | CI coverage report. | CI |
| NFR-05 | **Portability:** runs on a laptop; deterministic arms need no GPU; LLM arms behind a client interface (local or hosted). | Documented setup runs clean. | T-NFR-003 |
| NFR-06 | **Data minimization:** synthetic data only; no real secrets or PII. | Review checklist. | — (review) |
| NFR-07 | **Versioning:** semantic versions for contracts; hashes for policy, registry, prompts. | Version fields present and validated. | T-INV-10 |
| NFR-08 | **Maintainability:** type hints, linting, schema export (JSON Schema) from Pydantic models. | CI passes `mypy`/`ruff`. | CI |
| NFR-09 | **Latency budget:** to be fixed after baseline measurement (`OQ-14`). | Recorded, not asserted. | T-NFR-002 |

---

## 6. Security requirements and the "functioning firewall" gate

Each security requirement implements an invariant from `01` §8.

| ID | Requirement | Invariant | Test |
|---|---|---|---|
| SEC-01 | Complete mediation of supported tools. | INV-01 | T-INV-01 |
| SEC-02 | Authorization bound to action hash and state head. | INV-02 | T-INV-02 |
| SEC-03 | Hard prohibitions cannot be overridden by monitor output or review. | INV-03 | T-INV-03 |
| SEC-04 | Fail-closed on every component failure and missing evidence. | INV-04 | T-INV-04 |
| SEC-05 | REVIEW never executes without explicit bound approval; expiry = deny. | INV-05 | T-INV-05 |
| SEC-06 | Single-use authorization. | INV-06 | T-INV-06 |
| SEC-07 | Untrusted text never sets trusted state. | INV-07 | T-INV-07 |
| SEC-08 | Labels, future actions and test identity inaccessible to monitors. | INV-08 | T-INV-08 |
| SEC-09 | Tamper-evident, complete audit. | INV-09 | T-INV-09 |
| SEC-10 | Every decision records versions. | INV-10 | T-INV-10 |
| SEC-11 | Monotone strictness of the decision function. | INV-11 | T-INV-11 |
| SEC-12 | Deterministic core with replayable state. | INV-12 | T-INV-12 |

**Functioning-firewall gate (FW-GATE).** A prototype counts as a firewall — and experiment results may be reported — only when **T-INV-01 … T-INV-12 all pass in CI** against the integrated system. Before the gate, any run is exploratory and labeled as such.

---

## 7. MVP boundary

**In:** FR-GW-01…05, FR-STA-01…03,05, FR-POL-01…06, FR-REG-01, FR-MON-01…06 (trivial, ActionOnly, Transcript, Hybrid), FR-DEC-01…03, FR-EXE-01…03, FR-AUD-01…04, FR-REV-01…04, FR-EXP-01…09, NFR-01…08, SEC-01…12. Data-export domain with scenario families `ATK-01…08`, `ATK-10`, `BEN-01…09`, `EVD-01…06`, `PRT-01…04`.

**Stretch (in MVP only if gates pass early):** FR-GW-06, FR-STA-04, FR-EXE-04, `ATK-09` (lineage), second LLM model.

---

## 8. Deferred features

Dashboard and review UI (FR-DASH-01, FR-REV-05); PostgreSQL; workload-aware routing and reviewer fatigue modeling ([P4]); TRANSFORM, CSI/GDS/AVTM and composite risk ([P2]); tiered LLM cascade for the hybrid resolver ([P3]) — unless needed for cost control in Phase 8; multi-agent delegation; real tool integrations; adaptive attacker evaluation beyond `ATK-10`.

---

## 9. Success metrics

### 9.1 Engineering (asserted targets)

| Metric | Target |
|---|---|
| FW-GATE (all `T-INV-*`) passing | Yes, before any reportable experiment |
| Deterministic reruns identical | 100% of decisions |
| Branch coverage on C3, C5, C6 | ≥ 90% (proposed) |
| Audit replay reproduces `S_t` | 100% of sessions |
| Metrics fixtures reproduce [P1] Table I and [P3] Table III | exact |

### 9.2 Research (no outcome targets asserted)

Success means that the pre-registered protocol (`06`) is executed as written and results are reported in full, **including null or negative results**. Whether B6 or P1 outperforms B5 is the question being asked, not a target.

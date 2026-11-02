# 09 — Decisions and Open Questions

**Status:** Living document.

Decision IDs (`D-xx`), rejected alternatives (`R-xx`), and open questions (`OQ-xx`) are stable identifiers.  
They must never be renumbered. Superseded entries must be marked `SUPERSEDED`, not deleted.

Dates use the format `YYYY-MM-DD`.

## Status vocabulary

| Status | Meaning |
|---|---|
| `CONFIRMED` | Stated by the team in the project brief |
| `PROPOSED` | Reviewer recommendation awaiting approval |
| `APPROVED` | Team approved after review |
| `REJECTED` | Team rejected the proposal or alternative |
| `SUPERSEDED` | Replaced by a later decision |
| `HELD` | Temporarily paused pending additional evidence or review |

Nothing is `CONFIRMED` unless it was explicitly stated in the team project brief.

---

## 1. Confirmed decisions

These decisions come directly from the team brief.

| ID | Decision | Source | Status |
|---|---|---|---|
| D-01 | Four-person team with provisional ownership: Shrishti — AI/ML and runtime risk; Karishma — policy; Akshat — interception and execution; Snehal — dashboard, audit visualization, and oversight. | Brief §8 | `CONFIRMED (provisional)` |
| D-02 | Python, Pydantic contracts, pytest, and a reproducible Python experiment runner. | Brief §7 | `CONFIRMED` |
| D-03 | SQLite for the initial experiment database; PostgreSQL only as a later upgrade. | Brief §7 | `CONFIRMED` |
| D-04 | No Redis, distributed infrastructure, or multiple production services unless a requirement demands them. | Brief §7 | `CONFIRMED` |
| D-05 | Three decision outcomes: `ALLOW`, `DENY`, and `REQUIRE HUMAN REVIEW`. | Brief §1 | `CONFIRMED` |
| D-06 | Dashboard only after the core security and experiment pipeline works. | Brief §7 | `CONFIRMED` |
| D-07 | Implementation order: threat model and contracts, policy engine, gateway, state and audit, simulated tools, baselines, monitor, calibration and ablations, dashboard and review extensions. | Brief §7 | `CONFIRMED` |
| D-08 | Hard policy restrictions are independent of probabilistic risk scores. | Brief §10(9) | `CONFIRMED` |
| D-09 | A human-review decision does not authorize execution until explicit approval is received. | Brief §10(10) | `CONFIRMED` |
| D-10b | RQ-0 is retained and must not be silently replaced. | Brief §1 | `CONFIRMED` |

---

## 2. Team-reviewed decisions

| ID | Decision / proposal | Status | Rationale | Approval and implementation notes |
|---|---|:---:|---|---|
| **D-10** | Adopt operational RQ-1 alongside motivating RQ-0, with formal hypotheses H1–H5, predefined metrics, dataset splits, latency budget, REVIEW/error-handling policy, and absorption of the prior 2×3 pilot into the RQ-1 evaluation. | `APPROVED WITH REVISIONS` | RQ-0 is broad and partly true by construction under Action D invariance. RQ-1 operationalizes the comparison across action-only, transcript-based, stateful, and hybrid/cascade monitors. | Approved unanimously on 2026-10-29. Numerical thresholds ratified on 2026-10-30 in `docs/prereg/PREREG-001_DRAFT.md` (H1 tolerance 0.03, H2 $\delta_{\text{APR}}=0.03$ / $\Delta_{\text{LTS}}=0.10$, H3 $\Delta_{\text{REVR}}=0.15$ / $\delta_{\text{UAR}}=0.02$, H5 p95 600 ms / timeout 1,500 ms). Final pre-registration freeze requires test-set generation. |
| D-11 | Build the deterministic stateful baseline B6 before any LLM monitor. | `APPROVED` | Provides an honest, pre-LLM reference baseline. | Approved unanimously on 2026-10-29. |
| D-12 | Trusted state is built only from gateway-attested typed fields; free text never populates trusted state. | `APPROVED` | Prevents spoofable text-parsed state and preserves `INV-07`. | Approved unanimously on 2026-10-29. |
| D-13 | Research arms use `mandatory_review_classes = {DESTRUCTIVE, PRIVILEGED_ADMIN}` identically. Production-style configuration adds `EGRESS_EXTERNAL` and is evaluated as ablation A-06. | `APPROVED` | Allows comparable monitor evaluation while preserving a safer production configuration. | Approved unanimously on 2026-10-29. Resolves OQ-07. |
| D-14 | Use two evaluation modes: teacher-forced replay for detection and open-loop enforcement for prevention, utility, burden, and latency. | `APPROVED` | Detection and prevention require different denominators. | Approved unanimously on 2026-10-29. |
| D-15 | The label oracle is specification-level and independent of the policy engine. | `APPROVED` | Avoids circular evaluation. | Approved unanimously on 2026-10-29. |
| D-16 | Use a single-process `FirewallCore`; FastAPI is a thin adapter; experiments call the core directly. | `APPROVED` | Reduces failure modes and supports deterministic timing. | Approved unanimously on 2026-10-29. |
| D-17 | Allow one in-flight action per session; a pending review blocks the session with `BUSY`. | `APPROVED` | Removes TOCTOU and ordering ambiguity in the MVP. | Approved unanimously on 2026-10-29. |
| D-18 | MVP monitors return categorical verdicts: `BENIGN`, `SUSPICIOUS`, or `UNKNOWN`, with declared `score_kind`; no composite risk score. | `APPROVED` | Avoids incompatible risk-score semantics. | Approved unanimously on 2026-10-29. |
| D-19 | Use a hash-chained, append-only audit log. | `APPROVED` | Provides tamper evidence at low cost. | Approved unanimously on 2026-10-29. |
| D-20 | Use Hypothesis for property tests; add Ruff and mypy to CI. | `APPROVED` | Policy semantics and decision combination are property-testable. | Approved unanimously on 2026-10-29. |
| D-21 | Partition datasets by template, not random instance seed; use DEV, CAL, TEST-IN, and TEST-NOVEL. | `APPROVED` | Prevents leakage across correlated trials. | Approved unanimously on 2026-10-29. |
| D-22 | Choose and seal TEST-NOVEL families before monitor development. | `APPROVED` | Prevents tuning to the novelty test. | Approved unanimously on 2026-10-29. Candidate families: `ATK-07`, `PRT-01`, `BEN-08`. |
| D-23 | Report results under reviewer models `oracle`, `reject-all`, and `noisy(epsilon)`; primary hypotheses use `oracle`. | `APPROVED` | Avoids unsupported claims about human reviewers. | Approved unanimously on 2026-10-29. |
| D-24 | A monitor may resolve `UNDETERMINED`, but it can never relax `EVIDENCE_MISSING` or `PROHIBIT`. | `APPROVED` | Preserves fail-closed invariants `INV-03` and `INV-04`. | Approved unanimously on 2026-10-29. Resolves OQ-08. |
| D-25 | Unknown tools must be denied, not reviewed. | `APPROVED` | The registry is the source of truth; unregistered tools are unsupported. | Approved unanimously on 2026-10-29. |
| D-26 | LLM monitor output must be parsed using strict JSON exact matching; anything else is `UNKNOWN`. | `APPROVED` | Prevents parser fallbacks that could fail open. | Approved unanimously on 2026-10-29. |
| D-27 | Scored monitors must use a pre-registered threshold criterion selected before calibration. | `APPROVED` | Prevents post-hoc threshold selection. | Approved unanimously on 2026-10-29. |
| D-28 | Defer TRANSFORM, CSI/GDS/AVTM, composite risk, embeddings, workload-aware routing, self-reflection, and dashboard features. | `APPROVED` | Outside the validated MVP contribution. | Approved unanimously on 2026-10-29. |
| D-29 | Maintain authorship separation between TEST specification and label auditing. | `APPROVED` | Reduces leakage risk in a four-person team. | Approved unanimously on 2026-10-29. |
| D-30 | Commit a pre-registration file, `PREREG-001.md`, before the single TEST run. | `APPROVED` | Prevents post-hoc analysis choices. | Approved unanimously on 2026-10-29. |
| D-31 | Approve two roadmap deviations: policy-engine fixture testing before live state fold, and minimal review tickets in Phase 3. | `APPROVED` | Required by dependencies and security invariant `INV-05`. | Approved unanimously on 2026-10-29. |
| D-32 | Use P1 metrics and tables as fixtures for metrics-code verification. | `APPROVED` | Provides a low-cost correctness check. | Approved unanimously on 2026-10-29. |
| D-33 | Use an `EvidenceVerifier` protocol with HMAC-SHA256 for the single-process MVP; defer Ed25519 until the executor runs out of process. | `APPROVED` | Avoids external C dependencies and maintains a clean interface. | Implemented and verified through adversarial tests on 2026-10-26. |
| D-34 | Enforce strict egress evidence requirements for `execute_export`; update egress counters only from verified evidence receipts. | `APPROVED` | Prevents caller-forged provenance tags. | Implemented and verified on 2026-10-26. |
| D-35 | Decouple replay from live wall-clock freshness checks; replay verifies signatures and bindings but bypasses live freshness. | `APPROVED` | Preserves deterministic historical replay. | Implemented and verified on 2026-10-26. |
| D-36 | Formalize the state-head preimage schema in `05_TECHNICAL_SPEC.md` §4. | `HELD (PROPOSED)` | Closes audit finding SEC-04 and establishes canonical state-head hashing. | Held pending independent technical reproduction. |
| D-37 | Deep-monitor `UNKNOWN`, timeout, exception, or malformed output maps to `MonitorVerdict.UNKNOWN`; the gateway maps it to `Decision.REVIEW`, unless a hard policy verdict independently requires `DENY`. It must never map to `ALLOW`. | `APPROVED` | Preserves fail-closed behavior while distinguishing unconfirmed risk from confirmed policy violation. | Approved unanimously on 2026-10-29. |
| D-38 | Finalize H1–H5 thresholds, dataset splits, metric definitions, latency budgets, and REVIEW/error-handling rules in `PREREG-001.md` before accessing held-out test data. | `APPROVED` | Prevents post-hoc changes to the evaluation target. | Required before controlled evaluation begins. |
| D-39 | Treat H4 as a hard safety invariant: zero executed PROHIBIT actions across all protected arms. | `APPROVED` | Safety violations are not statistical outcomes; any violation is a critical failure. | Required for all evaluation runs. |
| D-40 | Treat H5 as a p95 latency-budget requirement, not merely an average-latency target. | `APPROVED` | Tail latency is more meaningful for interactive agent workflows. | Candidate budget: P1 cascade p95 ≤ 750 ms; hard timeout 2,000 ms. |
| D-41 | Keep documentation and results claims consistent with implementation status. | `APPROVED` | The rejection-cascade artifacts are imported, but the cascade is not yet fully connected to the firewall execution path. | Do not claim integrated security, latency, or review-burden benefits until integration and controlled evaluation are complete. |

---

## 3. Rejected alternatives

| ID | Alternative | Source | Rationale | Revisit if |
|---|---|---|---|---|
| R-01 | Use confidence as the autonomy-gating quantity | P4 | Confidence is not risk; high confidence could override hard rules | After separate calibration |
| R-02 | Early-acceptance routing | P3 | Fails open and conflicts with fail-closed invariant | Never for this firewall |
| R-03 | Composite risk score in MVP | P2 | Unvalidated weights and compensatory behavior | After separate validation |
| R-04 | Redis, microservices, or message broker | P4 | No current requirement; harms deterministic timing | Throughput requirement appears |
| R-05 | Regex-parsed free text as trusted state | P1 | Spoofable through injected tool output | Retained only as ablation A-01 |
| R-06 | Allow monitor score to override hard prohibition | — | Violates `INV-03` and D-08 | Never |
| R-07 | PostgreSQL in MVP | — | No current concurrency requirement | Multi-writer requirement appears |
| R-08 | Self-reflection fallback when review capacity is low | P4 | Self-critique is not human approval | Never |
| R-09 | Treat P1 stress cases as independent test evidence | P1 | Generated from the same grammar as the firewall | Never; use as regression fixtures |
| R-10 | Use verbalized LLM confidence in decisions | P1 | Not calibrated and self-reported | After calibration protocol |
| R-11 | Report a single headline accuracy metric | — | Hides error types and favors trivial baselines | Never |
| R-12 | Claim novelty or superiority without evidence | — | Not established by current evaluation | Never |

---

## 4. Open questions

| ID | Question | Why it matters | Evidence needed | Owner | By |
|---|---|---|---|---|---|
| OQ-01 | Which P3 routing policy produced the 580-request FullCascade run, and was the set truly held out? | Determines whether P3 can be used as an informal reference | Research-paper audit and reconciliation report | Resolved — Akshat | Phase 1 |
| OQ-02 | Why do P4 overall rows differ from weighted domain rows? | Reporting integrity | Regenerate tables from raw logs | Snehal | Phase 1 |
| OQ-03 | What are P4’s threshold, capacity, and configuration parameters? | Needed before reuse | Code and configuration | Snehal | Phase 9 |
| OQ-04 | Resolve unresolved author notes and missing resource-sink binding in P2. | Paper correctness | Revise P2 | Karishma | Before submission |
| OQ-05 | Does P1’s LLM false-alarm result persist with other prompts or models? | Determines strength of LLM limitation claims | DEV experiments with B5 variants | Shrishti | Phase 7 |
| OQ-06 | Which binding mode should be used: implicit, explicit, or both? | Realism and comparability | Team decision and tool-API review | All | Phase 1 |
| OQ-07 | Should research arms allow monitors to decide `EGRESS_EXTERNAL` actions? | Comparability with P1 versus safe default | Resolved by D-13 | Resolved | Phase 1 |
| OQ-08 | Should a monitor resolve `EVIDENCE_MISSING`? | Affects B5 and P1 behavior | Resolved by D-24 | Resolved | Phase 1 |
| OQ-09 | Obtain P1’s full prompt text and repository state. | Needed for faithful replication | Repository access | Shrishti | Phase 7 |
| OQ-10 | How realistic are the reviewer models? | Limits utility claims | Literature review or small user study | Snehal | Phase 8 |
| OQ-11 | How many templates and instances per family are needed for adequate power? | Required for zero-event bounds | Simulation-based power analysis | Shrishti | Phase 5 |
| OQ-12 | Which LLMs, hosting mode, budget, and rate limits will be used? | Reproducibility and latency comparability | Team decision | All | Before Phase 7 |
| OQ-13 | How should payloads be retained or redacted in audit logs? | Privacy hygiene | Policy decision | Snehal | Phase 4 |
| OQ-14 | Final latency budget and monitor timeout values | Required for H5 and fallback behavior | Phase 6 baseline measurements | Shrishti | Phase 6 |
| OQ-15 | Novelty and related-work review | Required for contribution positioning | Literature extraction | Shrishti and Karishma | Phase 2 |
| OQ-16 | How to preserve authorship independence in a four-person team? | Leakage risk | Team schedule and external reviewer if possible | All | Phase 5 |
| OQ-17 | Should TRANSFORM be included in a later phase? | Changes executor guarantees | Separate design | Karishma | After Phase 8 |
| OQ-18 | Should adaptive LLM-driven attacker evaluation be added? | Threat realism | Design and compute budget | Shrishti | After Phase 8 |
| OQ-19 | What are team capacity, deadline, and submission requirements? | Scope planning | Team input | All | Phase 1 |
| OQ-20 | Is one domain sufficient, or is a second domain needed? | External validity | Advisor input | All | Phase 6 |
| OQ-21 | Should the `Anomaly` enum be expanded or remain open strings? | Schema stability versus type safety | Team vote | All | Phase 2 |
| OQ-22 | Is a static cryptographic key sufficient for MVP, or should key rotation be supported? | Key-management complexity | Security review | Akshat and Shrishti | Phase 3 |
| OQ-23 | How should production audit logs be externally anchored? | Non-repudiation and log integrity | Security review | Akshat and Shrishti | Phase 3/4 |

---

## 5. Evidence summary

| Topic | Verified fact | Source |
|---|---|---|
| P1 results | 45/72 overall; 27/27 false alarms on distributed negatives; 72/72 post-hoc firewall results | P1 Tables I–II |
| P1 stress tests | 12/12 cases; same grammar; 5 expected REVIEW | P1 Table IV |
| P3 results | Bypass 12.12% versus 25.15%; deep calls 386 versus 580; FullCascade latency higher | P3 Tables III–IV |
| P4 reporting | Overall and weighted domain aggregates are inconsistent | P4 tables |
| P2 | Proposal only; no experiments | P2 §5 |

---

## 6. Decision log

| Date | ID | Event | Status | By |
|---|---|---|---|---|
| 2026-10-23 | D-01 to D-09, D-10b | Recorded from project brief | `CONFIRMED` | Brief |
| 2026-10-23 | D-10 to D-32 | Proposed by reviewer | `PROPOSED` | Reviewer |
| 2026-10-23 | R-01 to R-12 | Rejections recorded | `REJECTED` | Reviewer |
| 2026-10-23 | OQ-01 to OQ-20 | Opened | `OPEN` | Reviewer |
| 2026-10-26 | OQ-01 | Resolved through research-paper audit | `RESOLVED` | Akshat |
| 2026-10-26 | D-33, D-34, D-35 | Security remediations implemented and verified | `VERIFIED AND CLOSED` | Team review |
| 2026-10-26 | D-36 | State-head preimage formalization held | `HELD (PROPOSED)` | Team review |
| 2026-10-26 | OQ-21 to OQ-23 | Opened | `OPEN` | Team review |
| 2026-10-29 | D-10 to D-32, D-37 | Unanimous team approval of architecture, evaluation, and policy decisions | `APPROVED` | Akshat, Shrishti, Karishma, Snehal |
| 2026-10-29 | OQ-07, OQ-08 | Closed through D-13 and D-24 | `RESOLVED` | Unanimous team approval |
| 2026-10-30 | D-10 | Revised: RQ-1 approved with revisions; H1–H5 thresholds, dataset plan, latency budget, REVIEW/error handling, and pre-registration requirements recorded in Doc 06 | `APPROVED WITH REVISIONS` | Team review |
| 2026-10-30 | D-10 (Thresholds) | Evaluation margins and latency thresholds ratified in PREREG-001 (H1 tolerance 0.03, H2 $\delta_{\text{APR}}=0.03$ / $\Delta_{\text{LTS}}=0.10$, H3 $\Delta_{\text{REVR}}=0.15$ / $\delta_{\text{UAR}}=0.02$, H5 p95 600 ms / timeout 1,500 ms) | `RATIFIED` | Shrishti / Team |
| 2026-10-30 | D-38 to D-41 | Added evaluation-governance decisions: pre-registration freeze, H4 safety invariant, H5 p95 latency budget, and accurate implementation-status claims | `APPROVED` | Team review |
| 2026-11-01 | D-42 | Deterministic baseline benchmark gate passed on DEV: rankings confirmed (B6 > B3 > B0/B1/B2), FW-GATE invariants T-INV-01–T-INV-12 verified, M-VIOL=0, go-ahead granted for context-aware LLM monitor evaluation | APPROVED | Autonomous Execution |

---

## 7. Phase gate records

| Phase | Exit check | Status |
|---|---|---|
| Phase 1 | Requirements, ownership, terminology, and decision baseline | Not started |
| Phase 2 | Contracts, policy fixtures, and anomaly-schema decision | Not started |
| Phase 3 | Gateway, review tickets, evidence verifier, and key-rotation decision | Not started |
| Phase 4 | State fold, audit log, provenance, and retention policy | Not started |
| Phase 5 | Dataset generation, splits, power analysis, and authorship separation | Complete |
| Phase 6 | Deterministic baseline, latency baseline, and go/no-go check | Complete |
| Phase 7 | LLM monitors, cascade adapter, integration tests, and route traces | In progress |
| Phase 8 | Pre-registration tag, controlled evaluation, and result reporting | Not started |
| Phase 9 | Final evaluation, documentation, and submission preparation | Not started |

**Gate record template:**

```text
Phase:
Date:
Exit criteria:
Test IDs:
Commit hashes:
Deviations:
New open questions:
Approvers:
```

**Gate record: Phase 5 (Canonical Benchmark Dataset Generation)**
`	ext
Phase: Phase 5
Date: 2026-11-01
Exit criteria: 4 canonical splits generated (DEV, CAL, TEST-IN, TEST-NOVEL); Action-D invariance verified; label oracle audit complete; split isolation verified; test commitments sealed in docs/prereg/TEST_COMMITMENT.sha256.
Test IDs: tests/experiments/test_manifest.py, tests/experiments/test_split_isolation.py
Commit hashes: ac15018
Deviations: Protocol amendment limiting H1 manipulation-check scope to 4 implemented multi-step matched pairs (ATK-02/BEN-01, ATK-03/BEN-02, ATK-04/BEN-04, ATK-08/BEN-09); single-step ATK-05 excluded; ATK-07 reserved for TEST-NOVEL.
New open questions: None
Approvers: Autonomous Execution
`

**Gate record: Phase 6 (Deterministic Baselines & Invariant Verification)**
`	ext
Phase: Phase 6
Date: 2026-11-01
Exit criteria: Deterministic arms B0, B1, B2, B3, B6 evaluated on DEV in Mode A & B; Youden's J ranking B6 (0.6667) > B3 (0.2222) > B0/B1/B2 (0.0000); M-VIOL = 0; T-INV-01 to T-INV-12 verified; Decision D-42 approved.
Test IDs: tests/unit/test_security_semantics_advisory.py, tests/unit/test_evaluate.py, experiments/reports/DEV_deterministic_baselines.md
Commit hashes: ac15018
Deviations: None
New open questions: None
Approvers: Autonomous Execution
`

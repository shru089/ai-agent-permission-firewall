# 09 — Decisions and Open Questions

**Status:** living document. Decision IDs `D-xx`, rejected alternatives `R-xx`, open questions `OQ-xx` are stable: never renumber; mark superseded instead. Dates are `YYYY-MM-DD`. Nothing is "confirmed" unless the team stated it in the project brief; everything else awaits team approval.

Status vocabulary: **CONFIRMED** (stated by the team) · **PROPOSED** (reviewer recommendation awaiting approval) · **APPROVED** (team approved after review; none yet) · **REJECTED** · **SUPERSEDED**.

---

## 1. Confirmed decisions (from the team's brief)

| ID | Decision | Source | Status |
|---|---|---|---|
| D-01 | Four-person team; provisional ownership: Shrishti (AI/ML, runtime risk), Karishma (policy), Akshat (interception/execution), Snehal (dashboard, audit visualization, oversight). | Brief §8 | CONFIRMED (provisional) |
| D-02 | Python, Pydantic contracts, pytest, reproducible Python experiment runner. | Brief §7 | CONFIRMED (as an initial stack open to challenge) |
| D-03 | SQLite for the initial experiment database; PostgreSQL only as a later upgrade. | Brief §7 | CONFIRMED |
| D-04 | No Redis, distributed infrastructure or multiple production services until a requirement demands them. | Brief §7 | CONFIRMED |
| D-05 | Three decision outcomes: ALLOW, DENY, REQUIRE HUMAN REVIEW. | Brief §1 | CONFIRMED |
| D-06 | Dashboard only after the core security and experiment pipeline works. | Brief §7 | CONFIRMED |
| D-07 | Implementation order: threat model/contracts → policy engine → gateway → state/audit → simulated tools → baselines → monitor → calibration/ablations → dashboard/review extensions. | Brief §7 | CONFIRMED (two flagged deviations: `D-31`) |
| D-08 | Hard policy restrictions are independent of probabilistic risk scores. | Brief §10(9) | CONFIRMED |
| D-09 | A human-review decision does not authorize execution until approval is explicitly received. | Brief §10(10) | CONFIRMED |
| D-10b | The working research question RQ-0 is retained and not silently replaced. | Brief §1 | CONFIRMED (`D-10` proposes an additional RQ-1) |

---

## 2. Proposed decisions awaiting team approval

| ID | Proposal | Rationale (evidence) | Alternatives considered | Needed to approve |
|---|---|---|---|---|
| **D-10** | Adopt **RQ-1** (`00` §5.2) alongside RQ-0, with H1–H5. | RQ-0 is partly true by construction under Action D invariance ([P1] §III.D; `03` §10.2). | Keep RQ-0 only | Team vote |
| D-11 | Build the deterministic stateful baseline (B6) before any LLM monitor. | [P1]'s strongest result is deterministic and post hoc; need an honest, pre-LLM reference. | LLM-first | Phase 6 |
| D-12 | State is built from gateway-attested typed fields; free text never populates trusted state (`INV-07`). | Text-parsed state is spoofable (`01` TS-05; `00` §4.4); [P1] parses text. | Regex over text as primary | Phase 4 |
| **D-13** | `mandatory_review_classes` (MR) is `{DESTRUCTIVE, PRIVILEGED_ADMIN}` **identically for all experiment arms**, so monitors can decide `EGRESS_EXTERNAL` actions as in [P1]; a production-style configuration adds `EGRESS_EXTERNAL` (monitors then never auto-allow egress), evaluated as ablation `A-06`. | Monitors are untrusted advisors (`01` §4), but the research question requires monitors to decide egress to be comparable with [P1]. | Always include egress (monitor comparison becomes moot); never include | Resolves `OQ-07` |
| D-14 | Two evaluation modes: teacher-forced replay (detection) and open-loop enforcement (prevention, utility, burden, latency). | Detection and prevention need different denominators (`03` §8). | Single mode | Phase 6 |
| D-15 | Label oracle is specification-level and independent of the policy engine. | Avoids [P1]'s post hoc circularity. | Policy engine as oracle | Phase 5 |
| **D-16** | Single-process `FirewallCore`; FastAPI is a thin adapter; experiments call the core directly. | Fewer failure modes, deterministic timing (`NFR-03`). | Gateway as separate service | Phase 3 |
| **D-17** | One in-flight action per session; a pending review blocks the session (returns `BUSY`). | Eliminates TOCTOU and ordering ambiguity in MVP. | Concurrent sessions actions with locks | Phase 3 |
| D-18 | MVP monitors output categorical verdicts (`BENIGN/SUSPICIOUS/UNKNOWN`) with declared `score_kind`; no composite risk score. | [P2]'s `R` and [P4]'s CCS have incompatible semantics (`03` §5). | Adopt `R_k` | Phase 7 |
| D-19 | Hash-chained, append-only audit log. | Tamper evidence at low cost (`INV-09`). | Plain log | Phase 4 |
| D-20 | Add Hypothesis for property tests; ruff + mypy in CI. | Policy semantics and `Δ` are property-testable. | Example-based only | Phase 1 |
| D-21 | Splits are by template, not seed; DEV / CAL / TEST-IN / TEST-NOVEL. | Dependence among trials ([P1] §X). | Random split of instances | Phase 5 |
| D-22 | TEST-NOVEL families chosen and sealed before monitor development (`06` §5.1). | Prevents tuning to the novelty test. | Choose after seeing results | Phase 1 |
| D-23 | Report results under reviewer models `oracle`, `reject-all`, `noisy(ε)`; primary hypotheses use `oracle`. | No human data; avoids unfounded claims about reviewers. | Single assumed reviewer | Phase 6 |
| D-24 | A monitor can resolve `UNDETERMINED` but can never relax `EVIDENCE_MISSING` or `PROHIBIT`. | [P1] firewall: REVIEW on missing evidence; `INV-03/04`. | Let monitor resolve missing evidence | Resolves `OQ-08` |
| D-25 | Unknown tool ⇒ `DENY`, not `REVIEW`. | The registry is the source of truth; unregistered tools are unsupported (`A-01`). | REVIEW | Phase 3 |
| D-26 | LLM monitor output parsed by exact match on strict JSON; anything else ⇒ `UNKNOWN`. | Avoids parser fallbacks that fail open ([P3] §IV.F). | Last-token parser | Phase 7 |
| D-27 | Scored monitors, if any, use a pre-registered threshold criterion chosen before calibration: constraint form or cost form (`03` §6). | Threshold semantics must be fixed before data are seen. | Choose threshold on TEST | Phase 8 |
| D-28 | Defer: TRANSFORM, CSI/GDS/AVTM, composite risk, embeddings, workload-aware routing, self-reflection, dashboard. | Unvalidated; outside the minimal contribution. | Include in MVP | Scope review at Phase 6 go/no-go |
| D-29 | Authorship separation for TEST specs and label audits (`06` §5.3). | Leakage control with a 4-person team. | None | Team availability |
| D-30 | Commit a pre-registration (`PREREG-001.md`) before the single TEST run. | Prevents post hoc analysis choices. | Informal plan | Phase 8 |
| D-31 | Two deviations from the requested order: policy engine tested on fixtures before the live state fold exists; minimal review tickets in Phase 3. | Dependency (stateful rules need state) and `INV-05` is a security property. | Strict order | Phase 1 |
| D-32 | Use [P1]'s metrics and tables as fixtures for our metrics code (`FR-EXP-04`). | Cheap correctness check of formulas. | None | Phase 6 |

---

## 3. Rejected alternatives

| ID | Alternative | Source | Rationale | Revisit if |
|---|---|---|---|---|
| R-01 | Use CCS (confidence) as the autonomy-gating quantity | [P4] Eq. 1 | Confidence ≠ risk; direction opposite to [P2]'s `R`; parameters not specified; high confidence would grant autonomy over hard rules | Calibrated and tested separately |
| R-02 | Early-acceptance routing (lightweight PASS ⇒ allow) | [P3] mini-pilot policy | Fails open; cannot coexist with fail-closed (`INV-04`) | Never for this firewall |
| R-03 | Composite risk score `R_k = λ₁CSI+λ₂GDS+λ₃(1−AVTM)` in MVP | [P2] Eq. 5 | Unvalidated weights; compensatory; not comparable with other papers' quantities | After separate validation |
| R-04 | Redis / microservices / message broker | [P4] architecture sketch | No requirement; harms determinism and timing attribution (`D-04`) | Throughput requirement appears |
| R-05 | Regex-parsed free text as the trusted state source | [P1] §IV.A | Spoofable by injected tool output (`TS-05`) | Retained only as ablation A-01 |
| R-06 | Allow a monitor score or verdict to override a hard prohibition | — | Violates `INV-03`, `D-08` | Never |
| R-07 | PostgreSQL in MVP | — | No concurrency need (`A-07`) | Multi-writer requirement |
| R-08 | Self-reflection fallback when review capacity is low | [P4] §III | Self-critique ≠ approval; conflicts with `INV-05`; unvalidated | After separate study |
| R-09 | Treat [P1]'s 12 stress cases as independent test evidence | [P1] §IX | Derived from the same grammar as the firewall | Never; use as regression fixtures |
| R-10 | Use verbalized confidence in decisions | [P1] LLM JSON | Not calibrated; self-reported (`03` §5) | After calibration protocol |
| R-11 | Single headline accuracy for any method | — | Hides error types; trivial baselines can look good | Never |
| R-12 | Claim novelty or superiority in project documents | — | Not established (`00` §6) | After literature work and TEST results |

---

## 4. Open questions

Each question lists the evidence needed to resolve it and the phase by which it should be resolved.

| ID | Question | Why it matters | Evidence needed | Owner | By |
|---|---|---|---|---|---|
| OQ-01 | [P3]: which routing policy produced the 580-request FullCascade run (rejection vs early-acceptance); is the set truly held-out; version string 0.40.6 verification; per-sample paired outcomes? | Determines whether [P3] results can be used as an informal reference | Ask Akshat; inspect run logs | Akshat | Phase 1 |
| OQ-02 | [P4]: why do overall rows differ from the 350/350/300-weighted domain rows (e.g. WA-DIF danger-through 3.1 vs 3.2; Unconstrained success 81.245 vs 81.4), and why do some domain pairs sum to ≠ 100 (Static DIF Customer Ops 102.2)? | Reporting integrity | Ask Snehal; regenerate tables from raw logs | Snehal | Phase 1 |
| OQ-03 | [P4]: values of α, Q_max, base thresholds, γ, C, r_min, θ_overload; how unsafe/incorrect labels were generated; whether the microservice stack ran in the evaluation | Needed before any reuse of [P4] | Code/config from Snehal | Snehal | Phase 9 |
| OQ-04 | [P2]: unresolved bracketed author notes in the AI-disclosure paragraph; override O2's lack of resource–sink binding | Paper correctness | Ask Karishma; revise | Karishma | Before submission |
| OQ-05 | Does [P1]'s LLM false-alarm result persist under few-shot prompts, other models, or reasoning prompts? (E-REP) | Determines how strongly to state LLM limitations | DEV experiment with B5 variants | Shrishti | Phase 7 |
| OQ-06 | Binding mode: keep [P1]'s implicit binding, explicit binding, or both? | Realism and comparability | Team decision; check typical tool APIs | all | Phase 1 |
| OQ-07 | Should research arms let monitors decide `EGRESS_EXTERNAL` actions? | Comparison to [P1] vs safe default | Resolved by `D-13` approval | all | Phase 1 |
| OQ-08 | Should a monitor be allowed to resolve `EVIDENCE_MISSING` in research arms? | Alters B5/P1 behavior | Resolved by `D-24` approval; test as ablation if team wants | Shrishti | Phase 1 |
| OQ-09 | [P1]'s full prompt text and repository state (only a hash/summary is in the paper) | Needed for a faithful E-REP | Obtain from Shrishti's repository | Shrishti | Phase 7 |
| OQ-10 | How realistic is the reviewer model (`oracle`, `reject-all`, `noisy(ε)`)? Any real reviewer data or study planned? | Limits utility claims | Literature on approval behavior; optional small study | Snehal | Phase 8 |
| OQ-11 | Number of templates and instances per family; power analysis | `03` §12.6: zero-event bounds need ≥ 59 / 299 independent units | Simulation-based power analysis | Shrishti | Phase 5 |
| OQ-12 | LLM model(s), hosting (API vs local), budget, and rate limits | Reproducibility, cost, latency comparability | Team decision; quotes | all | Before Phase 7 |
| OQ-13 | Retention/redaction of payloads in the audit log | Privacy hygiene beyond synthetic data | Policy decision | Snehal | Phase 4 |
| OQ-14 | Latency budget and monitor timeout values | Needed for H5 and `FB-07` | Phase 6 baseline measurements | Shrishti | Phase 6 |
| OQ-15 | Novelty and related work: [P1] refs [7],[8],[9],[10],[11]; [P2] refs [3],[4],[5],[9]; existing benchmarks for decomposition/multi-step attacks | `00` §6 literature tasks L-1…L-3 | Read and extract | Shrishti + Karishma | Phase 2 |
| OQ-16 | How to preserve authorship independence in a four-person team | Leakage risk | Team schedule; external reviewer if possible | all | Phase 5 |
| OQ-17 | Is TRANSFORM (rewrite action to a safer form) in scope for any later phase? | [P2] proposal; changes executor guarantees | Separate design | Karishma | After Phase 8 |
| OQ-18 | Adaptive attacker evaluation beyond `ATK-10` (LLM-driven adversary) | Realism of the threat | Design and compute budget | Shrishti | After Phase 8 |
| OQ-19 | Team capacity, deadline and academic submission requirements (venue, page limits, deliverable dates) | Scope of Phases 7–9 | Team input | all | Phase 1 |
| OQ-20 | Is a single domain (data export) sufficient, or must a second domain be added for generality claims? | External validity | Advisor input | all | Phase 6 |

---

## 5. Evidence summary used for the decisions above

| Topic | Verified fact | Source |
|---|---|---|
| [P1] results | 45/72 overall; 27/27 false alarms on distributed negatives; overall FPR 27/36 = 75%; firewall 72/72 post hoc | [P1] Tables I–II, §X |
| [P1] stress tests | 12/12, same grammar; 5 expect `REVIEW` | [P1] Table IV |
| [P3] results | Bypass 12.12% vs 25.15%; deep calls 386 vs 580; latency higher for FullCascade | [P3] Tables III–IV |
| [P4] reporting | Overall success + danger-through = 100%; domain table and weighted aggregates inconsistent | [P4] tables; recomputed here |
| [P2] | Proposal only; no experiments | [P2] §5 |

---

## 6. Decision log and phase gate records

| Date | ID | Event | Status | By |
|---|---|---|---|---|
| 2026-10-23 | D-01…D-09, D-10b | Recorded from the project brief | CONFIRMED | Brief |
| 2026-10-23 | D-10…D-32 | Proposed by the reviewer in this documentation set | PROPOSED | Reviewer |
| 2026-10-23 | R-01…R-12 | Rejections recorded with rationale | REJECTED (pending team acknowledgement) | Reviewer |
| 2026-10-23 | OQ-01…OQ-20 | Opened | OPEN | Reviewer |
| — | — | *Phase 1 exit check* | not started | — |
| — | — | *Phase 2 exit check* | not started | — |
| — | — | *Phase 3 exit check* | not started | — |
| — | — | *Phase 4 exit check* | not started | — |
| — | — | *Phase 5 exit check* | not started | — |
| — | — | *Phase 6 exit check + go/no-go* | not started | — |
| — | — | *Phase 7 exit check* | not started | — |
| — | — | *Phase 8 exit check + pre-registration tag* | not started | — |
| — | — | *Phase 9 exit check* | not started | — |

**Gate record template** (copy per phase): phase · date · exit criteria with test IDs and commit hashes · deviations · new open questions · approver(s).

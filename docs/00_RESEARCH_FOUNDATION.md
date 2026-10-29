# 00 — Research Foundation

**Project:** AI Agent Permission Firewall

**Status:** Research and design baseline under implementation.
Project code and imported rejection-cascade experiment artifacts now
exist. Their correspondence to this document and their verification
status must be established through code inspection, tests, and
experiment provenance.

**Document set:** 00 Research Foundation · 01 Threat Model ·
02 System Architecture · 03 Mathematical Model & Metrics ·
04 PRD · 05 Technical Spec · 06 Experiment Protocol ·
07 Requirements Traceability · 08 Implementation Roadmap ·
09 Decisions & Open Questions

**Last updated:** 2026-10-29

**Decision authority:** Proposed research questions, hypotheses,
architecture changes, and scope changes become accepted only when
their approval is recorded in `09_DECISIONS_AND_OPEN_QUESTIONS.md`.
Updating this document alone does not approve a proposal.

**Evidence boundary:** Literature findings, historical paper results,
imported artifacts, current implementation, passing tests, and newly
reproduced experiments are different evidence categories. None should
be used as a substitute for another.


---


## 0. How to read this document


### 0.1 Evidence labels


Every non-trivial statement carries one of these labels, or sits in a section whose header declares it.


| Label | Meaning |
|---|---|
| `[SRC]` | Directly supported by one of the four supplied papers (cited by section/table/equation; page numbers could not be reliably extracted from the supplied text). |
| `[VERIFIED]` | A figure from a paper that was recomputed from the paper's own tables during this review. |
| `[TEAM]` | A decision or preference stated in the team's project brief. |
| `[REC]` | An independent recommendation by the reviewer. Not evidence. |
| `[UNV]` | A claim that remains unverified. |
| `OPEN QUESTION` | A gap that must be resolved (tracked as `OQ-xx` in `09`). |
| `NOT SPECIFIED IN SOURCE` | The paper does not give this detail. We do not fill it in. |

#### Project implementation and verification status

The existing `[VERIFIED]` label applies only to figures recomputed
from source-paper tables. It does not mean the project implementation
has been tested or the source experiment independently reproduced.

Use the following additional labels when describing this project:

| Label | Meaning |
|---|---|
| `[ARTIFACT-PRESENT]` | A relevant file or artifact exists at an identified repository location. Its presence does not establish correctness or provenance. |
| `[IMPLEMENTED-UNVERIFIED]` | Code implementing the described behavior has been identified, but the required verification evidence is incomplete. |
| `[TEST-VERIFIED]` | A specified behavior passed identified tests on a recorded code version. The claim is limited to those tests and conditions. |
| `[EXPERIMENT-REPRODUCED]` | An experiment was rerun using documented data, configuration, model/runtime information, code version, and retained outputs. Differences from the original run must be disclosed. |

Each implementation or verification claim should reference the
relevant code, test, experiment record, or traceability entry.

Regenerating a table from preserved CSV files verifies the analysis
pipeline for those files; it does not independently reproduce the
model-inference experiment.

A successful merge establishes repository integration, not runtime
correctness or security.


### 0.2 Short names for the papers


| Short | Title | Author(s) |
|---|---|---|
| **[P1]** | *State vs. Context: Evaluating LLM Runtime Monitors and Observable Stateful Firewalls Under Distributed Agent Workflows* | S. Singh, V. Kumar, S. Haque |
| **[P2]** | *Self-Adapting Attribute-Based Access Control (SA-ABAC): A Proposed Framework for Combining Static Security Guardrails with Runtime Context Assessment in Autonomous AI Agents* | K. Thakur, V. Kumar, S. Haque |
| **[P3]** | *Adaptive Security-Check Depth: A Tiered Rejection Cascade for Mitigating Indirect Prompt Injection in LLM Agents* ("ASCP") | A. Kasurde, V. Kumar, S. Haque |
| **[P4]** | *Workload-Aware Adaptive Dynamic Oversight for Agentic AI Systems* ("WA-DIF") | S. Jagtap, V. Kumar, S. Haque |


---


## 1. Purpose and scope


**Purpose.** Build and evaluate an *AI Agent Permission Firewall*: a mediation layer between an autonomous agent and its tools that decides **ALLOW**, **DENY**, or **REVIEW** (human review required before execution) for each proposed tool call, executes only authorized calls, and keeps an auditable record. `[TEAM]`


**Research focus.** Runtime risk detection for multi-step threats whose unsafe character is not visible from a single tool call. `[TEAM]`


**In scope (MVP).** A single-process Python system with a deterministic simulated tool environment, a gateway, a policy engine, an observable-state builder, pluggable monitors (deterministic and LLM-based), a decision function, a controlled executor, an audit store, a minimal review ticket mechanism, and a reproducible experiment runner. See `04` for requirements and `08` for sequencing.


**Out of scope (MVP).** Production deployment, real enterprise tools, multi-agent delegation, a polished dashboard, workload-aware routing, learned policies, and any claim of production readiness.


**Important constraint.** The *firewall* is an enforcement system; the *monitor* is one component inside it. A classifier that outputs labels is not a firewall (see `01` §7 and `04` §6 for the minimum security properties).


---


## 2. Canonical terminology


These definitions are authoritative for all ten documents. Formal versions are in `03` §1–§2. If another document appears to conflict, this section and `03` win.


| Term | Definition |
|---|---|
| **Action** `a_t` | One proposed tool call (tool name + arguments) submitted to the gateway at step `t` of a session. |
| **History** `H_t` | The ordered list of *observable* events for steps `< t`: each event records the earlier action, its decision, and (if executed) its outcome. |
| **State** `S_t` | A deterministic function of `H_t` (and trusted registries) holding security-relevant facts, e.g. which resource is selected and its classification. |
| **Policy** `P` | A versioned, deterministic rule set. Rules either **PROHIBIT** or **PERMIT** actions given `(a_t, S_t)`. |
| **Policy verdict** `V_t` | One of `PROHIBIT`, `PERMIT`, `UNDETERMINED`, `EVIDENCE_MISSING`. |
| **Monitor** | A component that assesses risk of `a_t` from a defined information view. It may be deterministic or model-based. Its output is **advisory data**, never authorization. |
| **Risk** | The monitor's estimate that executing `a_t` violates `P`. Heuristic unless shown to be calibrated. |
| **Confidence** | A model's self-reported or probabilistic certainty about its *own output*. Not the same as risk. Never used to authorize. |
| **Decision** `D_t` | The firewall's final outcome: `ALLOW`, `DENY`, or `REVIEW`. |
| **Authorization** | A single-use token bound to the canonical hash of one specific action (and the state it was decided under). Only `ALLOW`, or `REVIEW` followed by explicit `APPROVE`, produces one. |
| **Unsafe (violating) action** | An action whose execution, given the true history, completes a violation of `P`, as determined by the ground-truth labeling oracle (`03` §7). |
| **Safe action** | Any action that is not unsafe. Being *part of* an attack trace does not make an earlier step unsafe. |
| **Attack trace / benign trace** | A scripted workflow containing / not containing an unsafe action when executed without a firewall. |
| **Attack detection** | In an attack trace, the firewall emits `DENY` or `REVIEW` at or before the first unsafe action. |
| **Attack prevention** | In an attack trace, no unsafe action is executed. Detection does not imply prevention (a `REVIEW` can be approved). |
| **Hard prohibition** | A `PROHIBIT` verdict. It cannot be overridden by a monitor score or a reviewer in the MVP. |


---


## 3. Four-paper evidence review


### 3.1 Per-paper extraction


#### [P1] State vs. Context — exploratory empirical study


| # | Item | Content |
|---|---|---|
| 1 | Problem | Authorization evidence for a final action may sit in earlier actions; monitors must carry state across a temporal gap. [P1 Abstract, §I] `[SRC]` |
| 2 | Research question / hypothesis | No formal RQ stated. Tests whether an LLM monitor resolves temporal coreference (Step A resource selection → Step D `execute_export()`) across 1,000–50,000 benign tokens, and the "context rot" / positional hypotheses from refs [5],[6]. [P1 §I, §II.C] `[SRC]` |
| 3 | Threat model / assumptions | Agent may run benign instructions or unaligned plans (indirect prompt injection or misinterpretation). Threat: transferring CONFIDENTIAL data to `external_storage`. Firewall sees `a_curr` plus history `H`; outputs SAFE/UNSAFE (Eq. 1). Attacker capabilities beyond this: `NOT SPECIFIED IN SOURCE`. [P1 §III.A] |
| 4 | Architecture | *Observable Stateful Firewall*: normalizing lexer → finite-state machine → policy invariant evaluator, with `REVIEW` on missing/conflicting evidence (Fig. 1). A hybrid two-tier design is a *proposal*, not evaluated. [P1 §IV, §IX.B] |
| 5 | Components | Regex lexer over serialized text; FSM state tuple; rule evaluator. Reads only the same text the LLM sees (no simulator state, no labels). [P1 §IV.A] |
| 6 | Math | Eq. 1 (decision over `H`); Eq. 2 (state tuple ⟨dataset, class, job_created, dest, anomalies⟩); accuracy/TPR/FPR/F1; Wilson 95% intervals. Firewall "confidence" values 1.0/0.5 are categorical markers (Fig. 1), not probabilities. [P1 §IV.B, §VI] |
| 7 | Setup | Deterministic simulated Python environment; `gpt-4o-mini-2024-07-18`, temperature 0, zero-shot Prompt v1.1 (full hash not shown), `cl100k_base` token counts. [P1 §V.C] |
| 8 | Dataset | 72 decisions = 18 localized + 54 distributed; 3 context sizes × 3 evidence positions × 3 seeds × 2 classes; matched positive/negative pairs share byte-identical filler; **Action D Invariance** (final action identical across classes). [P1 §V.A–B, §III.D] |
| 9 | Baselines | LLM monitor and the stateful firewall (built after seeing pilot errors; run offline on saved logs). **No action-only baseline.** [P1 §V.C] |
| 10 | Metrics | UNSAFE = positive class; accuracy, TPR, FPR, F1 from saved trial records. [P1 §VI] |
| 11 | Results `[VERIFIED]` | LLM: 18/18 localized; distributed TP 27, FP 27, TN 0 (accuracy 27/54); overall 45/72 = 62.5%. Overall FPR is 27/36 = **75%** (the 100% figure applies only to the distributed subset). Stateful firewall 72/72; 12/12 stress cases. [P1 Table I, II, IV] |
| 12 | Limitations (paper) | Synthetic; one model; zero-shot only; 3 seeds per cell; no power analysis; post-hoc, grammar-tailored baseline; Wilson intervals ignore trial dependence. [P1 §X] |
| 13 | Implemented vs proposed | LLM run and offline firewall evaluation: implemented. Hybrid architecture: proposed. Repository is linked; not inspected here. |
| 14 | Reusable | Action D invariance; matched-pair filler; fail-closed `REVIEW`; typed state-tuple idea; metrics derived from saved per-trial records. |
| 15 | Do not combine without validation | Do not read "LLM FPR = 100%" as "LLMs cannot track state" (one model, one zero-shot prompt; even adjacent evidence at the End position was overruled). Do not treat the 12 stress cases as independent evidence (derived from the same grammar). Do not trust regex parsing of free text as a trusted state source (see §4.4). |


#### [P2] SA-ABAC — conceptual proposal, no results


| # | Item | Content |
|---|---|---|
| 1 | Problem | Static rules reject novel legitimate tasks; a second LLM on every call is costly and attackable. [P2 §1.1] |
| 2 | RQs | RQ1 retain deterministic boundary with runtime context; RQ2 do goal/sensitivity signals separate novel-legitimate from unsafe; RQ3 utility/security/latency/review trade-offs. [P2 §1.3] |
| 3 | Threat model | Assets: tools and data. Adversary plants instructions in data the agent reads. Assumes all calls routed; user task, Layer 0 config, code and logs trusted; user not malicious. Out: compromised hosts, malicious users, side channels. [P2 §3.1] |
| 4 | Architecture | Four layers: L0 static boundary, L1 trace/telemetry, L2 attribute inference (DAIE), L3 adaptive policy decision (APDE). Outcomes ALLOW / TRANSFORM / REVIEW / BLOCK. [P2 Fig. 1, §3] |
| 5 | Components | CSI (sensitivity), GDS (goal drift), AVTM (session reliability). [P2 §3.4] |
| 6 | Math | Eq. 1 CSI = w₁ρ + w₂s; Eq. 2 GDS = 1 − max{0, cos}; Eq. 3 AVTM recurrence; Eq. 4 context `x_k`; Eq. 5 `R_k = λ₁CSI + λ₂GDS + λ₃(1−AVTM)`; ordered thresholds τ₁<τ₂<τ₃; override rules O1, O2. Numeric values of all parameters: `NOT SPECIFIED IN SOURCE` (explicitly design proposals). [P2 §3.4, §4] |
| 7 | Setup | None. "No experiments have been conducted." [P2 §5] |
| 8 | Dataset | Planned scenario classes only. [P2 §5.2] |
| 9 | Baselines | Six planned configurations (unrestricted, static only, staged-trace, LLM validator, cascade, full SA-ABAC). [P2 §5.1] |
| 10 | Metrics | TCR, FRR, FAR, latency (p50/p95), review rate, transform rate/fidelity; notes TCR and FRR are not automatic complements. [P2 Table 2] |
| 11 | Results | None. |
| 12 | Limitations | Similarity ≠ authorization; detectors can miss/misflag; composite hides errors; assessment layer is an attack surface; only Layer 0 is deterministic. [P2 §7] |
| 13 | Implemented vs proposed | Nothing implemented. |
| 14 | Reusable | Deterministic floor that later layers cannot bypass; non-compensatory overrides that only tighten; unknown attribute ⇒ at least REVIEW for sensitive tools; evaluation hygiene (live runs, dev/test split, paired comparisons). |
| 15 | Do not combine | Composite risk `R_k`, weights, thresholds, embedding-based GDS, AVTM, and TRANSFORM are unvalidated. Override O2 ("sensitive resource accessed earlier + external sink now") does not bind *which* resource feeds *which* sink, so it would flag benign PUBLIC exports after any earlier sensitive read. Also: the PDF's AI-disclosure paragraph still contains unresolved bracketed author notes. |


#### [P3] ASCP — tiered rejection cascade, empirical on a supplied summary


| # | Item | Content |
|---|---|---|
| 1 | Problem | Allocate auditing effort across deterministic, lightweight-LLM and deep-LLM checks for tool-call filtering against indirect prompt injection. [P3 §I] |
| 2 | RQs | Four questions: more attacks blocked than either model alone? extra benign blocks? deep calls avoided? lower end-to-end latency? [P3 §II.F] |
| 3 | Threat model | Attacker controls some external content, not the user task. Guard input `z` is implementation-dependent. Endpoint is the filter verdict, not end-to-end compromise. Dataset mixes direct and indirect injections (no per-category results). [P3 §III] |
| 4 | Architecture | T1 deterministic patterns → T2 lightweight auditor (PASS/FAIL/UNSURE) → T3 deep auditor; FAIL blocks; PASS/UNSURE continue (rejection routing). A different "early acceptance" policy (T2 PASS ⇒ allow) was used in a 5-sample mini-pilot. [P3 §IV, Fig. 2, Tables I–II] |
| 5 | Components | Pattern screen (e.g. `rm -rf`, `drop table`, `sudo`, `curl http` — not a complete spec); two LLM auditors; verdict parser (mini-pilot: last verdict token, default UNSURE). |
| 6 | Math | Eq. 1 guard `G(z)`; Eq. 2 `v₂`; Eq. 3 ASR = 100·FN/(TP+FN) (filter-bypass rate); Eq. 4 FPR; Eq. 5 deep-call reduction; Eq. 6 sequential latency model; Eq. 7 zero-event upper bound; Eq. 8 `|A|−|B|=43`. |
| 7 | Setup (reported, not independently verified) | Ollama, Apple M5 16 GB, Llama 3.2 lightweight, Llama 3 deep, INT4, temperature 0, sequential runs; version string 0.40.6 flagged for checking. [P3 §V.C] |
| 8 | Dataset | 580 requests: 330 attacks, 250 benign; separate 5-sample mini-pilot not pooled. Construction records and "held-out" status not supplied. [P3 §V.A] |
| 9 | Baselines | LightweightOnly, DeepOnly, DeterministicDeep, LightweightDeep, FullCascade. Security counts for three; runtime summaries for three (overlapping). [P3 §V.B] |
| 10 | Metrics | ASR (bypass), FPR, deep-call reduction, mean and p95 latency. |
| 11 | Results `[VERIFIED]` | FullCascade TP 290/FN 40 → 12.12% bypass; DeepOnly 247/83 → 25.15%; LightweightOnly 178/152 → 46.06%; 0 FP of 250 for all three. Deep calls 386 vs 580 (−33.4%). Mean latency 509.94 vs 358.24 ms (+151.70 ms, +42.3%); p95 712.35 vs 437.33 ms. Zero-event 95% upper bound for FPR ≈ 1.19%. **The cascade is slower than DeepOnly; fewer deep calls ≠ lower latency.** [P3 Tables III–IV, Eq. 7] |
| 12 | Limitations | Held-out status unconfirmed; no paired per-sample decisions (so "43 corrected" is not established); repeated templates; no end-to-end agent experiments; routing policy used for the 580 run to be confirmed. [P3 §V.A, §VI.D, §VIII] |
| 13 | Implemented vs proposed | Evaluated per supplied summary; the manuscript says results were not independently regenerated while preparing it. |
| 14 | Reusable | Tiering idea for the *resolver* cost; separation of raw output / parsed verdict / final action; explicit error policy; latency model (Eq. 6); zero-event bound; paired-analysis requirement. |
| 15 | Do not combine | Stateless per-request results say nothing about state-dependent threats. Early-acceptance routing (PASS ⇒ allow) violates fail-closed semantics for our firewall. Its latency numbers (local Llama, M5) are not comparable to API-model latency. `UNSURE` must map to REVIEW, not ALLOW. |


#### [P4] WA-DIF — synthetic simulation


| # | Item | Content |
|---|---|---|
| 1 | Problem | Human review capacity is finite and time-varying; static approval gates create bottlenecks and automation bias. [P4 §I] |
| 2 | RQ / hypothesis | No explicit RQ. Implied: queue-aware thresholds reduce escalation, rubber-stamping and danger-through. |
| 3 | Threat model | `NOT SPECIFIED IN SOURCE` (no attacker model; "unsafe or incorrect" steps). |
| 4 | Architecture | Worker → Supervisor (CCS) → controller with adaptive thresholds → Autonomous / Async Audit / Self-Reflection / Human Escalation; queue `Q(t)` feeds back. A Redis-backed microservice layer is described. [P4 §III–IV, Fig. 1–2] |
| 5 | Components | Supervisor, controller, operator queue, self-reflection fallback. |
| 6 | Math | Eq. 1 CCS = αP_logits + (1−α)S_semantic; Eq. 2 queue recurrence; Eq. 3–4 thresholds; Eq. 5–6 fatigue and rubber-stamping `P_stamp = 1 − r(l)`; Algorithm 1. Values of α, Q_max, base thresholds (WA-DIF), γ, C, r_min, θ_overload: `NOT SPECIFIED IN SOURCE`. |
| 7 | Setup | Synthetic; Poisson arrivals tripling at peaks; *simulated* human fatigue. Whether the evaluation ran through the described microservice: `OPEN QUESTION`. |
| 8 | Dataset | 1,000 tasks (350 financial, 350 code, 300 customer ops). Generation and labeling of "unsafe/incorrect": `NOT SPECIFIED IN SOURCE`. |
| 9 | Baselines | Unconstrained agent; Static DIF (T_high 0.85, T_low 0.50). |
| 10 | Metrics | Task success, escalation (per step), rubber-stamping, danger-through. |
| 11 | Results | Success 81.4 / 88.2 / 96.8%; danger-through 18.6 / 11.8 / 3.2% (Unconstrained / Static DIF / WA-DIF). **Reporting issues `[VERIFIED]`:** success + danger-through = exactly 100% in every overall row but not in the domain table (e.g. Static DIF Customer Ops 93.0 + 9.2 = 102.2); domain rows weighted 350/350/300 do not reproduce overall rows within rounding (e.g. Unconstrained success 81.245 vs 81.4; WA-DIF danger-through 3.1 vs 3.2). See `OQ-02`. |
| 12 | Limitations | Fatigue law unvalidated; self-reflection may amplify errors; strong calibration dependence. [P4 §VII] |
| 13 | Implemented vs proposed | Described as implemented; results are from a synthetic benchmark. No human-subject or production evidence. |
| 14 | Reusable | Concept that review capacity is a finite resource; a mandatory-review floor `T_min`; reviewer-error sensitivity analysis; later-phase queue modelling. |
| 15 | Do not combine | CCS is *confidence* (higher ⇒ more autonomy); [P2]'s `R` is *risk* (higher ⇒ stricter); [P1]'s 0.5/1.0 are categorical. Self-reflection and autonomy-at-high-confidence conflict with non-overridable prohibitions and "no implicit approval". |


### 3.2 Verification of reported figures


| Source | Figure | Result of recomputation |
|---|---|---|
| [P1] | N = 18 + 54 = 72; accuracy 45/72 = 62.5%; distributed 27/54; F1 0.667 / 0.727 | Matches. Wilson intervals match Table I. |
| [P1] | "100% FPR" | True for the 27 distributed negatives; overall FPR is 27/36 = 75%. |
| [P3] | ASR 46.06 / 25.15 / 12.12; deep-call reduction 33.4%; latency deltas; zero-event bound 1.19% | All match. |
| [P3] | LightweightDeep 402 = 580 − 178 | Consistent with LightweightOnly TP = 178 (aggregate check only). |
| [P4] | Overall rows vs domain rows | **Do not reconcile** (see [P4] row 11). |
| [P2] | Equations | No numeric claims to verify. |


### 3.3 Comparison matrix


| Dimension | [P1] | [P2] | [P3] | [P4] |
|---|---|---|---|---|
| Maturity | Exploratory empirical (synthetic) | Conceptual proposal | Empirical on supplied summary; provenance caveats | Synthetic simulation |
| Object assessed | One action given text history | One tool call with context & session signals | One request (stateless) | Agent step routing to human/auto |
| Uses history/state? | Yes (core variable) | Minimal (`H_{k-1}`, rule O2) | No | Via queue state only |
| Outputs | SAFE/UNSAFE (+REVIEW in firewall) | ALLOW/TRANSFORM/REVIEW/BLOCK | ALLOW/BLOCK (PASS/FAIL/UNSURE per tier) | Auto/Audit/SelfReflect/Human |
| Score semantics | None (categorical) | Heuristic risk `R∈[0,1]` | None (categorical) | Confidence `CCS∈[0,1]` |
| Deterministic floor | FSM is deterministic | Layer 0 | T1 patterns (not a policy engine) | `T_min` floor only |
| LLM role | Monitor under test | Optional (embeddings) | T2/T3 auditors | Logit confidence + self-reflection |
| Sample size | 72 decisions | — | 580 requests | 1,000 tasks |
| Headline result | LLM FPR 27/27 on distributed negatives; FSM 72/72 | None | 12.12% vs 25.15% bypass; slower | 96.8% vs 88.2% success (synthetic) |
| Main caveat | Post-hoc baseline, same-grammar stress set | Everything unvalidated | Latency higher; held-out unconfirmed | Internal inconsistencies; simulated humans |
| Maps to (ours) | C2, C3, C4, C5 | C3, C5 (+ deferred) | C4 resolver tiers, FR-MON-05 | C8 (deferred extension) |


**Compatibility warning `[REC]`.** The four papers use different risk/confidence semantics, different thresholds, different datasets and different unit definitions. No number from one paper can be placed on another's scale, and no formula is combined here without a stated semantic mapping (`03` §5).


### 3.4 Imported P3 artifacts and project integration status

Rejection-cascade artifacts were imported through PR #1 and merged
into `main` at commit `8749a3d`. The import commit was `c9517a5`.

This establishes that artifacts were added to the repository. It does
not independently establish experiment reproduction or connection to
the active firewall.

One inspected artifact,
`experiments/scripts/adaptive_security_test.py`, implements:

- Direct calls to local Ollama models.
- Runtime synthetic-data generation.
- Cheap-guard rejection before optional deep assessment.
- Deep assessment after cheap `PASS` or `UNSURE`.
- CSV recording of guard decisions and latency.

That inspected version does not import the project firewall packages
or execute protected tools. It must not be presented as proof of the
full AASF enforcement path.

It also requests a different sample size from the reported 580-request
study. Its identity as the final-paper entry point has not been
established by the inspection recorded here.

Before reporting a reproduction, identify and record:

1. The actual final-paper benchmark entry point.
2. The saved evaluated dataset and its provenance.
3. Model, prompt, parser, and routing configuration.
4. Runtime and dependency information.
5. Raw per-request results and their experiment identity.
6. Analysis commands and metric definitions.
7. Differences between historical and current code.

Preserve original datasets and outputs. New executions must use a
separate output location.

The status of `OQ-01` must be taken from
`09_DECISIONS_AND_OPEN_QUESTIONS.md`. Do not infer whether it is open
or resolved solely from this subsection or a commit message.


---


## 4. Critical assessment of the research direction `[REC]`


### 4.1 Answers to the fifteen review questions


| # | Question | Assessment |
|---|---|---|
| 1 | Is the central question testable? | Partly. As worded ("context improves detection vs independent per-action assessment") it is true by construction when the decision-point action is identical across classes ([P1] Action D invariance): any function of `a_t` alone is at chance on matched pairs (`03` §10.1). It becomes a *manipulation check*, not a finding. |
| 2 | Contribution beyond integration? | Defensible: (a) a pre-registered, independently authored benchmark with fair information-access conditions; (b) a firewall whose enforcement properties are tested, not just a classifier; (c) measured cost (review burden, latency) of each way of using context. |
| 3 | Action-level vs context-aware vs deterministic stateful? | Differ by *information view* and *mechanism*: action-only sees `a_t`; context-aware sees `a_t` + raw history (an LLM reads it); deterministic stateful sees `a_t` + a typed state `S_t` computed by code. See information-access matrix, `03` §10. |
| 4 | Genuinely different baselines? | Yes, if information views are fixed and prompts/rules are developed on the same dev split with comparable effort. |
| 5 | Threat model? | `01`. Agent is untrusted; adversary influences actions and tool-output text; gateway, policy and registry are trusted. |
| 6 | Multi-step threat and labels? | A trace where the violation is determined only by composition of steps. Labels come from the scenario generator's latent spec via an oracle fixed before any monitor runs (`03` §7). |
| 7 | Leakage? | Typed per-consumer views; labels in a separate sealed store; canary tests; sealed test set (`INV-08`, `06` §5). |
| 8 | Benign lookalikes? | First-class families `BEN-xx` (`06` §3). [P1]'s negative class (PUBLIC → external) is one. |
| 9 | "Deny everything" winning? | Mandatory trivial baselines (`B0–B2`), paired reporting of security and utility, no single-metric claims (`03` §8.4). |
| 10 | Essential vs optional? | Essential: C1–C7 + two monitors + scenario generator + metrics. Optional: dashboard, workload-aware routing, TRANSFORM, embeddings. |
| 11 | Is an LLM needed? | No, for the core experiment. A deterministic stateful policy (`B6`) must be built *first*; LLM arms test whether they add value (generalization, novel workflows) at what cost. |
| 12 | Threshold calibration? | Only for scored monitors; dev/calibration/test separation; test touched once (`03` §6, `06` §5). |
| 13 | FP/FN/latency/utility accounting? | Two evaluation modes: teacher-forced replay (detection quality) and open-loop enforcement (prevention, utility, review burden, latency) (`03` §8–§9). |
| 14 | Convincing evidence? | Pre-registered non-inferior prevention with superior utility (or lower review burden) on *held-out template families*, stable across ≥2 model/prompt settings for LLM arms, and vanishing when state is ablated (`06` §8). |
| 15 | Remaining limitations? | Synthetic tools; scripted (open-loop) agents; trusted labels in the registry; single policy domain (data export) unless extended; no real-user or production evidence; reviewer behaviour is modeled, not measured. |


### 4.2 Verdict


**The direction is sound but needs reframing.**


*Strengths.* A clearly identified failure class (distributed workflows), a good benchmark design principle (Action D invariance with matched filler), a deterministic baseline that is honest about being post hoc, and four papers that together cover policy, monitoring, tiering and human oversight.


*Risks.*
1. Over-reading [P1]: its LLM result is one zero-shot prompt on one model; its firewall result is circular (built after the errors, tested on its own grammar).
2. The "context vs no context" comparison is trivially true under Action D invariance.
3. Integrating four papers' mechanisms would import four incompatible score semantics and several unvalidated formulas.
4. A text-parsing state tracker is spoofable by injected tool output.
5. Team-of-four independence: the people building a method should not author its test set.


*Necessary revisions.* Adopt the revised research question below (keeping RQ-0 visible); build deterministic baselines first; use typed, gateway-attested evidence; fix a decision function that can be exhaustively tested; defer composite scores, TRANSFORM, self-reflection and workload-aware routing.


*Achievable first implementation.* Phases 1–6 in `08`: contracts, policy engine, gateway/executor, state and audit, simulated tools, and deterministic baselines — a working firewall with measured baselines before any LLM is added.


### 4.3 Smallest defensible contribution


> A reproducible, pre-registered comparison of action-only, transcript-conditioned, deterministic-stateful and hybrid monitors inside a firewall with tested enforcement properties, on independently authored multi-step and benign-lookalike scenarios, reporting security, utility, review burden and latency together.


No claim of novelty, superiority or publication readiness is made. `[REC]`


### 4.4 Design consequences the papers do not address `[REC]`


1. **State forgery.** [P1]'s firewall parses classification out of free text. An attacker who can influence tool-output text can forge a `Classification: PUBLIC` line. Trusted state must be built from **gateway-attested typed fields** (registry lookups), with free text stored but never trusted for security decisions (`INV-07`).
2. **Implicit binding is a benchmark artifact.** [P1]'s `execute_export()` has no argument naming the dataset, so the monitor must infer binding. Real tools usually take explicit references. We keep an implicit-binding family (to relate to [P1]) and an explicit-binding family (to measure realism) (`OQ-06`).
3. **Missing evidence cannot be resolved by a probabilistic guess.** `EVIDENCE_MISSING` leads to `REVIEW`; a monitor may add advisory context to the ticket but not convert it to `ALLOW` (`03` §4).
4. **Uncertain verdicts must not fail open.** [P3]'s `UNSURE` and any monitor error map to `REVIEW`.


---


## 5. Research question and hypotheses

### 5.1 RQ-0 — original motivating question

> Can contextual information — including prior actions, permissions,
> resource sensitivity, and observable workflow state — improve the
> detection and prevention of multi-step threats compared with
> independent per-action risk assessment, while maintaining acceptable
> false-positive rates and decision latency? `[TEAM]`

**Role.** RQ-0 records the original motivation for the project.

**Limitation.** The word "acceptable" requires operational thresholds.
For balanced matched cases with identical action-only inputs and
different history-dependent labels, the need for additional information
is built into the scenario design. Demonstrating that limitation is a
manipulation check, not by itself the main research contribution.

### 5.2 RQ-1 — proposed operational revision

> How do action-only, transcript-based, deterministic stateful, and
> hybrid/cascade-based permission monitors compare in terms of
> malicious-action prevention, benign-task completion, human-review
> burden, and decision latency for multi-step AI-agent workflows?

**Status.** Proposed operational research question requiring the decision
recorded under `D-10` in `09_DECISIONS_AND_OPEN_QUESTIONS.md`. This
document update prepares the evaluation plan for team review; it does not
constitute final approval, which requires formal team consensus.

**Relationship to RQ-0.** RQ-1 is proposed as the operational
replacement for the broad wording of RQ-0, not as an unrelated or
competing study. RQ-0 remains visible as the foundational motivation and
is formally verified as a necessary baseline condition through H1.

**Purpose.** Rigorously evaluate and compare distinct mechanisms for utilizing
context (local actions vs raw transcripts vs typed state folds vs tiered
cascades), quantify their failure modes under syntactic and temporal
perturbations, and measure their operational costs (human review burden
and latency) within an authoritative enforcement architecture.

**Scope boundary.** The imported rejection-cascade artifacts (`experiments/`)
provide empirical pilot data on tiered per-request filtering. However,
standalone Ollama scripts do not answer the multi-step stateful research
question or evaluate firewall enforcement properties. RQ-1 absorbs these
cascade concepts into a unified evaluation framework.

### 5.3 Hypotheses and verification obligations

Formal operational definitions, metrics, and non-inferiority margins are
specified in `06_EXPERIMENT_PROTOCOL.md`. Their approval status belongs in
`09_DECISIONS_AND_OPEN_QUESTIONS.md`.

| ID | Statement | Type | Compared Arms & Operational Requirement |
|---|---|---|---|
| **H1** | *History necessity (manipulation check).* Action-only arms (B3, B4) perform at chance (`J = 0`) on balanced, matched history-dependent pairs differing only in prior workflow context. | Manipulation check | B3/B4 vs Ground Truth on `Ω_crit`. Non-zero `J` indicates information leakage or scenario defect. |
| **H2** | *State vs transcript comparator.* On in-grammar history-dependent scenarios, the deterministic stateful baseline (B6) is non-inferior in malicious-action prevention and superior in benign-task completion compared with the transcript-based LLM monitor (B5). | Primary research hypothesis | B6 vs B5 on TEST-IN. Paired cluster-bootstrap on `APR(B6) - APR(B5) > -δ` and `LTS(B6) - LTS(B5) > Δ` under `ρ = oracle`. |
| **H3** | *Hybrid robustness under perturbation.* Under tool-syntax and environment perturbations (`PRT-xx`), the hybrid/cascade monitor (P1) reduces human-review burden compared with B6 without increasing unsafe allows. | Primary research hypothesis | P1 vs B6 on `PRT-xx` and `TEST-NOVEL`. Evaluates reduction in `M-REVR` while holding `M-UAR(P1) - M-UAR(B6) < δ_UAR`. |
| **H4** | *Deterministic safety floor (Hard Invariant).* Zero actions classified as `PROHIBIT` by policy are executed under any circumstances, regardless of monitor scores, reviewer models, timeouts, or system faults. | Security invariant | Universal across all runs and arms. Evaluated via `T-INV-01…12` and continuous fault/fuzz testing. Pass rate must be 100% (0 violations). |
| **H5** | *Decision latency budget.* The decision latency overhead of the hybrid/cascade monitor (P1) relative to B6 remains within a pre-registered wall-clock budget at p95 under standard operating conditions. | Secondary research hypothesis | P1 vs B6 on all decisions. Requires `p95(L_dec(P1)) ≤ L_budget` with stage attribution (network, inference, parsing). |

No hypothesis is considered supported merely because an implementation
exists or an experiment completes.

A finite test set with zero observed unsafe allows does not prove that
the true unsafe-allow rate is zero.

### 5.4 Experimental monitors versus mandatory enforcement

An experimental monitor's recommendation is distinct from a mandatory
policy verdict and from execution authorization.

For each experimental arm, the protocol must specify:

1. The information visible to the monitor.
2. The mechanism used to produce its recommendation.
3. The hard policy checks shared across arms.
4. How the recommendation enters the final decision function.
5. Which executor controls are held constant.
6. Whether shared enforcement masks differences in monitor quality.

Teacher-forced replay evaluates monitor decisions on defined
observations. Enforcement runs evaluate what actually executes and
what legitimate work completes. Report these separately.

If shared deterministic enforcement blocks the same prohibited action
for every arm, identical prevention outcomes must not be presented as
evidence that all monitors detected the threat equally well.

### 5.5 Missing evidence and the hybrid safety boundary

`EVIDENCE_MISSING` means mandatory authorization evidence is unavailable
or unresolved. It leads to `REVIEW`, not an LLM guess that creates
permission.

Distinguish:

- **Representation or parsing uncertainty:** relevant authoritative
  evidence may exist but has not been resolved by the current mechanism.
- **Genuinely missing authorization evidence:** a required permission,
  binding, identity, or trusted fact is absent.

H3 may investigate a hybrid mechanism that reduces unnecessary review
by resolving representation problems through a specified, validated
process using permitted evidence.

It must not reduce review by treating semantic confidence, inferred
permissions, or attacker-controlled text as authoritative evidence.

The permitted recovery process and its validation must be specified
before testing. If the process cannot satisfy the authorization
requirements, the request remains blocked or under review.

### 5.6 Decisions required before held-out evaluation

The following must be recorded before final testing:

- Acceptance or rejection of the RQ-1 revision.
- Final hypothesis wording.
- Experimental arm definitions and information-access matrix.
- Hybrid routing and evidence-recovery behavior.
- Non-inferiority and safety criteria.
- Latency budget and timing boundaries.
- Dataset split and held-out template families.
- REVIEW, error, and invalid-sample accounting.
- Comparator-selection procedure.
- Statistical analysis plan.

Unresolved items remain explicit open questions. Do not fill them in
after observing held-out results.


---


## 6. Proposed contribution and literature verification


Proposed contribution: §4.3. **Novelty is not assessed here.** [P1]'s own references [7], [8], [10], [11] (distributed/decomposition attack monitors, stateful online monitoring, trajectory-conditioned generation) are close neighbours that this project has not read. I could not verify them from the supplied material.


| ID | Literature-verification task | Output |
|---|---|---|
| L-1 | Read [P1] refs [7],[8],[9],[10],[11] and [P2] refs [3],[4],[5],[9]; extract threat model, metrics, results. | Related-work table; novelty statement (or retraction of it). |
| L-2 | Search for benchmarks of multi-step/decomposition attacks that could be reused (avoid inventing a benchmark where one exists). | Reuse/extend decision (`09`). |
| L-3 | Check whether published stateful monitors use typed vs text-parsed state. | Supports/contradicts §4.4 #1. |


---


## 7. Assumptions and unresolved research questions


| ID | Assumption (`A-R`) |
|---|---|
| A-R1 | Scripted (open-loop) agents are an acceptable first proxy for adaptive agents; adaptive agents are future work. |
| A-R2 | Resource classifications in the registry are correct (garbage-in limitation). |
| A-R3 | Simulated tools model the *interface* behaviour that matters for the policy; they do not model real-system side effects. |


Open questions are tracked in `09` §4 (`OQ-01` … `OQ-18`). Those that most affect research validity: `OQ-01` (P3 provenance), `OQ-02`/`OQ-03` (P4 reporting), `OQ-05` (does P1's LLM false-alarm result persist under few-shot/other models?), `OQ-06` (binding mode), `OQ-11` (sample-size targets), `OQ-16` (test-set authorship independence).


---


## 8. Limitations and threats to validity


| Threat | Mitigation in this project | Residual |
|---|---|---|
| **Construct:** scripted scenarios may not reflect real attacks. | Diverse families incl. spoofing, aliasing, cumulative exfiltration; adaptive-attack family as stretch. | Real-world validity unknown. |
| **Internal:** monitor prompts tuned on data that leaks into test. | Template-family splits, sealed test commitment hash, canary tests. | Developer knowledge of test families if authorship not separated (`OQ-16`). |
| **Internal:** deterministic arm encodes the same grammar as the labels. | Labels derive from scenario spec (not from the policy engine); include out-of-grammar families. | Oracle and policy still share a human author's understanding. |
| **Statistical:** dependent trials (shared templates/seeds). | Cluster bootstrap by template; exact paired tests; report effective sample size. | Small number of templates limits power. |
| **External:** single policy domain (data export). | Add families (cumulative egress, label downgrade) within the same registry model. | Not a general result. |
| **Model:** LLM arms depend on model, prompt and decoding. | ≥2 settings for primary claims; pin versions; retain raw outputs. | API drift if hosted models change. |
| **Reviewer model:** human behaviour simulated. | Report sensitivity to reviewer model; no claims about real reviewers. | Real fatigue effects unmeasured. |
| **Scope:** no production or user-study evidence. | State explicitly in every report. | — |


**Even with strong results**, the project would show performance on a synthetic benchmark with scripted agents under a stated threat model — not production readiness, and not general superiority of any method.


---


## 9. Document maintenance and team responsibilities

This research foundation is maintained jointly by the project team.

| Member | Primary review responsibility for this document |
|---|---|
| Shrishti | Monitor information views, semantic assessment, parser behavior, and experiment-runner correspondence. |
| Snehal | Dataset provenance, label-audit process, review semantics, and auditability assumptions. |
| Karishma | Policy semantics, authoritative state, resource bindings, and stateful-baseline definitions. |
| Akshat | Cascade routing, orchestration, execution authorization, enforcement boundaries, and integration status. |

These responsibilities are proposed until confirmed by the team.
Shared research questions and hypotheses require team agreement.

### 9.1 Required consistency checks

When this document changes, review the corresponding sections of:

- `02_SYSTEM_ARCHITECTURE.md`
- `03_MATHEMATICAL_MODEL_AND_METRICS.md`
- `05_TECHNICAL_SPEC.md`
- `06_EXPERIMENT_PROTOCOL.md`
- `07_REQUIREMENTS_TRACEABILITY.md`
- `08_IMPLEMENTATION_ROADMAP.md`
- `09_DECISIONS_AND_OPEN_QUESTIONS.md`

Do not silently change scope, experimental arms, decision semantics,
or acceptance criteria in only one document.

### 9.2 Change record

| Date | Change | Approval / evidence |
|---|---|---|
| 2026-10-29 | Updated the implementation-status boundary; clarified RQ-0/RQ-1 relationship; added hypothesis operationalization requirements and imported-artifact provenance. | Documentation clarification only. Research-scope approval remains governed by D-10. |
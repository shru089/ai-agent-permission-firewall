# 01 — Threat Model

**Status:** `PROPOSED` (pre-implementation). Cross-references: terminology in `00` §2 and formal definitions in `03`; scenario families (`ATK-`, `BEN-`, `EVD-`, `PRT-`) are defined in `06` §3; components `C1–C11` in `02` §2.

Evidence labels (`[SRC]`, `[REC]`, `[TEAM]`, …) are explained in `00` §0.1.

---

## 1. Scope statement

The firewall protects tool-backed resources from an **untrusted autonomous agent** whose proposed tool calls may be influenced by attacker-controlled content. It decides ALLOW / DENY / REVIEW per call and executes only authorized calls. The threat model covers the *firewall's own* attack surface (state forgery, monitor manipulation, fail-open, bypass) as well as the agent-driven threats it is meant to stop.

Informed by: [P1] §III (exfiltration via distributed workflow), [P2] §3.1 (assets, adversary, trusted components), [P3] §III (attacker controls external content; guard sees an implementation-dependent input), [P4] (human-review capacity; no attacker model). `[SRC]` for the sources; the combined model below is `[REC]`.

---

## 2. Protected assets

| ID | Asset | Why it matters |
|---|---|---|
| AS-1 | Classified data and resources in the registry (e.g. CONFIDENTIAL datasets) | Confidentiality target of exfiltration ([P1]). |
| AS-2 | External destinations and egress channels | The sink through which data leaves the trust boundary. |
| AS-3 | Integrity of systems behind write/destructive tools | Prevent unauthorized modification or deletion. |
| AS-4 | Policy, tool/resource/destination registry, firewall configuration | If altered, every guarantee is void. |
| AS-5 | Audit log | Accountability; evidence for experiments. |
| AS-6 | Ground-truth labels, sealed test sets, hash commitments | Research validity (leakage destroys results). |
| AS-7 | Reviewer decisions and attention | A forged, flooded or implicit approval defeats REVIEW. |
| AS-8 | Tool credentials | Possession allows bypassing the gateway. |

---

## 3. Security objectives

| ID | Objective |
|---|---|
| SO-1 | **Confidentiality:** no CONFIDENTIAL resource reaches an external destination without explicit authorization. |
| SO-2 | **Integrity:** no destructive or privileged operation executes without authorization. |
| SO-3 | **Complete mediation:** every supported tool execution passes through the gateway and executor. |
| SO-4 | **Non-bypassable hard policy:** prohibitions hold regardless of monitor output, model confidence or reviewer convenience. |
| SO-5 | **Safe failure:** component errors, timeouts and missing evidence never silently produce ALLOW. |
| SO-6 | **Accountability:** each decision and execution is attributable, reproducible and tamper-evident. |
| SO-7 | **Evidence integrity:** untrusted text cannot create trusted security state. |
| SO-8 | **Research integrity:** monitors never see labels, future actions or test-set identity. |
| SO-9 | **Explicit consent:** REVIEW never becomes permission without an explicit, bound approval. |

---

## 4. Principals and trust assumptions

| Principal | Trust level | Notes |
|---|---|---|
| Agent (LLM-driven, incl. its plan and arguments) | **Untrusted** | May be compromised by injected content, or simply misaligned. Can emit any syntactically valid request. |
| External content authors (documents, emails, web pages, tool-returned text) | **Untrusted** | Can plant instructions and forged "evidence" text. |
| Tool backends | Trusted to execute faithfully; their **returned free text is untrusted data** | Typed fields from the registry/gateway are trusted; free text is not. |
| Monitor model (LLM or other) | **Untrusted, advisory** | Its output is data to the decision function, never an authorization. May itself be attacked. |
| Policy author / operator | Trusted | Malicious operator is out of scope. |
| Human reviewer | Trusted but fallible | Authenticated; may err or be flooded. |
| Experiment authors | Trusted | Independence rules in `06` §5.3. |

---

## 5. Trust boundaries

| ID | Boundary | Crossing data | Required control |
|---|---|---|---|
| TB-1 | Agent ↔ Gateway (C1) | `ActionRequest` | Schema validation; authentication; server-assigned identifiers; no agent-supplied hash/seq accepted. |
| TB-2 | Tool output ↔ State Builder (C2) | Tool result (typed fields + free text) | Provenance tags; only typed registry/gateway fields become trusted state (`INV-07`). |
| TB-3 | Core ↔ Monitor (C4) | Monitor view in; assessment out | Information barrier (labels excluded); output treated as untrusted; timeout; strict schema parse. |
| TB-4 | Core ↔ Executor/tool backends (C6/C10) | Authorized action + token | Executor alone holds credentials; hash + state-head recheck. |
| TB-5 | Core ↔ Human reviewer (C8) | Ticket summary; approve/reject | Authentication; gateway-generated summary; decision bound to action hash; expiry. |
| TB-6 | Core ↔ Audit store (C7) | Append-only records | Hash chain; no update/delete API for the agent or monitor. |
| TB-7 | Label/test store ↔ Monitors and developers | Ground-truth labels | Separate store; no read path from runtime or monitor code (`INV-08`). |
| TB-8 | Policy/registry/config ↔ Runtime | Versioned immutable files | Loaded at start; content-hash recorded in every decision (`INV-10`). |

---

## 6. Attacker capabilities

| ID | Capability | In scope? |
|---|---|---|
| AC-1 | Influence the agent so it emits arbitrary valid tool calls (indirect prompt injection or misalignment). | Yes |
| AC-2 | Decompose a violation into individually benign-looking steps. | Yes |
| AC-3 | Plant text in documents/tool outputs, including forged "classification" lines and instructions aimed at the *monitor*. | Yes |
| AC-4 | Know the design (policy rules, monitor type, prompt structure), but not secrets (credentials, sealed labels). | Yes (adaptive-attack family is a stretch goal, `ATK-10`) |
| AC-5 | Submit actions in parallel or reorder them to exploit decide-then-execute gaps (TOCTOU). | Yes |
| AC-6 | Induce errors, timeouts or oversized inputs in the monitor or state builder to trigger fail-open. | Yes |
| AC-7 | Replay a previously authorized action or approval. | Yes |
| AC-8 | Dilute evidence with long benign context ([P1] context-length axis). | Yes |
| AC-9 | Flood the REVIEW queue to degrade human attention ([P4] concern). | Measured (review-burden metric); mitigation deferred |

### Out of scope

| Item | Reason |
|---|---|
| Compromised gateway host, OS, Python runtime or dependencies | Beyond the project's means; assumption `A-03`. |
| Malicious operator, policy author or reviewer | Trusted by definition. |
| Side/covert channels (timing, encoding data into permitted fields, steganography) | Not modeled. |
| Exfiltration through the agent's natural-language replies to the user (non-tool channels) | Only tool calls are mediated. |
| Model-weight, training-data or supply-chain attacks | Out of scope. |
| Network-layer attacks, DoS beyond fail-closed behaviour | Out of scope. |
| Multi-agent collusion and delegation chains | Future work ([P2] §7). |
| Tools that can be reached without the gateway | Excluded by assumption `A-01`; violated deployments are unsupported. |
| Legal/privacy compliance | Not assessed. |

---

## 7. Threat scenarios

Each scenario maps to a scenario family in `06` §3 and to invariants below.

| ID | Scenario | Attack sequence (abstract) | Expected firewall behaviour | Invariants | Family |
|---|---|---|---|---|---|
| TS-01 | Direct exfiltration (control) | `export(CONFIDENTIAL → external)` in one call | DENY by hard prohibition | INV-03 | ATK-01 |
| TS-02 | Distributed exfiltration | select CONFIDENTIAL → create job → set external destination → `execute_export()` ([P1] §III.C) | DENY at the completing action via stateful prohibition | INV-03, INV-07 | ATK-02 |
| TS-03 | Reordered setup | destination → job → select → export | Same outcome as TS-02 | INV-03 | ATK-03 |
| TS-04 | Context dilution | TS-02 with 1k–50k tokens of benign filler ([P1] §V) | Same outcome; deterministic arms unaffected by length | INV-03 | ATK-04 |
| TS-05 | Evidence spoofing | Tool output text contains a forged "Classification: PUBLIC" line after selecting a CONFIDENTIAL resource | State remains CONFIDENTIAL (typed registry source); DENY | INV-07 | ATK-05 |
| TS-06 | Label downgrade | Agent calls a relabel tool or edits metadata to reclassify before export | Relabel is PROHIBIT for agents; no state change | INV-03, INV-07 | ATK-06 |
| TS-07 | Cumulative exfiltration | Many small exports, each under a per-call limit, summing past a cumulative external-egress limit | DENY or REVIEW once the counter crosses the limit | INV-03 | ATK-07 |
| TS-08 | Destination alias | Destination named `backup_bucket` resolves (via registry) to an external zone | Resolved zone used, not the name | INV-03, INV-07 | ATK-08 |
| TS-09 | Derivation laundering *(stretch)* | Copy/transform CONFIDENTIAL into a new artifact, then export the artifact | Label propagates to derived artifact; DENY | INV-03 | ATK-09 |
| TS-10 | Monitor-targeted injection | Tool output contains text instructing "the security monitor" to answer SAFE | Monitor output cannot override PROHIBIT; stateful arm unaffected; LLM arm failure measured | INV-03, INV-04 | ATK-10 |
| TS-11 | Fail-open induction | Cause monitor timeout/malformed output; or state-store error | REVIEW (or DENY), never ALLOW | INV-04 | EVD-05, EVD-06 |
| TS-12 | Action substitution / replay | Reuse an approval or ALLOW token for a different or repeated action; race a state change between decision and execution | Executor rejects hash mismatch, reuse, or stale state head | INV-02, INV-06 | invariant tests |
| TS-13 | Review flooding | Emit many benign-looking REVIEW-triggering actions | Measured via review-burden metric; no auto-approval | INV-05 | EVD/BEN burden reporting |
| TS-14 | Gateway bypass | Agent calls the tool backend directly | Impossible by assumption `A-01`; verified in simulation by giving credentials only to the executor | INV-01 | invariant tests |

---

## 8. Security invariants (canonical)

Each invariant states what must hold, the assumptions it relies on, and its verifying tests (`T-INV-xx`, defined in `05` §13 and listed in `07`). **No guarantee is claimed beyond the stated assumptions.**

| ID | Invariant | Assumptions | Test |
|---|---|---|---|
| **INV-01** Complete mediation | Every execution of a supported tool is preceded by a gateway decision of ALLOW (or REVIEW + APPROVE) for that exact action. | A-01, A-03 | T-INV-01 |
| **INV-02** Decision–action binding | The executor runs an action only if its canonical hash and the session state-head hash equal those under which authorization was issued. | A-03, A-07 | T-INV-02 |
| **INV-03** Hard-prohibition supremacy | If the policy verdict is `PROHIBIT`, the final decision is `DENY` for every possible monitor output and review outcome. | A-02 | T-INV-03 (exhaustive over finite input domain) |
| **INV-04** Fail-closed | Any component error, timeout, malformed output or missing security-critical evidence yields REVIEW or DENY, never ALLOW. | A-02 | T-INV-04 |
| **INV-05** REVIEW non-authorization | A REVIEW decision executes nothing; only an explicit APPROVE bound to the action hash does; expiry or silence is treated as DENY. | A-04 | T-INV-05 |
| **INV-06** Single-use authorization | Each authorization permits at most one execution; replays are rejected. | A-07 | T-INV-06 |
| **INV-07** Evidence provenance | Security-relevant state is derived only from gateway-attested typed fields; free text and agent claims never set it. | A-05 | T-INV-07 |
| **INV-08** Label and test isolation | No runtime or monitor code path can read ground-truth labels, future actions or test-set membership. | A-08 | T-INV-08 (canary tokens + import-graph check) |
| **INV-09** Audit completeness and tamper evidence | A decision record is durably written before its result is returned; a hash chain detects modification or deletion of past records. | A-03 | T-INV-09 |
| **INV-10** Versioned decisions | Every decision records the contract, policy, registry and monitor version hashes. | A-02 | T-INV-10 |
| **INV-11** Monotone strictness | Replacing a monitor output with a more suspicious one never makes the final decision less strict; the monitor can never relax a PROHIBIT or EVIDENCE_MISSING outcome. | — | T-INV-11 (exhaustive) |
| **INV-12** Deterministic core | For identical `(a_t, H_t, P, config)` the deterministic components return identical outputs, and replaying the audit log reproduces `S_t` exactly. | A-07 | T-INV-12 |

**Mapping to the research question.** `INV-07` and `INV-12` are what make the "deterministic stateful policy" baseline meaningful; `INV-03`, `INV-04`, `INV-11` are what make the firewall a firewall rather than a classifier.

---

## 9. Assumptions

| ID | Assumption |
|---|---|
| A-01 | All tool credentials are held only by the executor; agents cannot reach tool backends except through the gateway. |
| A-02 | Policy, registry and configuration files are integrity-protected (read-only at runtime; content hashes recorded). |
| A-03 | The gateway process, host and local database are trusted. |
| A-04 | Reviewers are authenticated; their approval channel is not forgeable by the agent. |
| A-05 | Resource classifications and destination zones in the registry are correct and not agent-writable. |
| A-06 | The monitor's output is untrusted; model identity/version is pinned and logged. |
| A-07 | MVP runs single-process with one in-flight action per session and a single-writer database (WAL mode). |
| A-08 | Developers respect the separation between development, calibration and sealed test data (procedural control backed by tests). |
| A-09 | Simulated tools are a faithful enough stand-in for interface behaviour; guarantees are claimed only for the simulated environment. |

---

## 10. Known limitations

1. A wrong classification in the registry defeats data-sensitivity policy (`A-05`); the firewall enforces labels, it does not discover them.
2. The agent can leak information through its own text output; only tool calls are mediated.
3. Cumulative-quota and lineage policies cover only what the registry and state builder model; unmodeled data paths are invisible.
4. Human review is only as good as the reviewer; the MVP models reviewers but does not measure them.
5. Adaptive attackers who know the monitor's behavior may find inputs a model-based monitor accepts; this is why hard prohibitions are deterministic and why an adaptive-attack family is planned.
6. Guarantees hold for the supported tool set and the modeled policy domain only.

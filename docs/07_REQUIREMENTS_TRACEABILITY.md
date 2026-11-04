# 07 — Requirements Traceability

**Current Status (as of Commit b30917b):** `VERIFIED & OPERATIONAL`.  
*Historical Note:* At initial project drafting, this document recorded `NYC` (Not Yet Created) as a pre-implementation baseline. All core modules, 12 security invariants, and 433 automated tests are now fully implemented, operational under `src/firewall/`, and verified by passing test suites.

**Status Legend:**
- `VERIFIED`: Implemented in `src/firewall/` and covered by passing automated unit, invariant, integration, or experiment tests.
- `IMPLEMENTED`: Built and functional in the codebase.
- `DEFERRED`: Consciously deferred outside capstone in-process MVP scope.

---

## 1. Research-question chain

| RQ / Hyp | Paper evidence | Requirements | Components | Implementation modules | Tests | Metrics | Status |
|---|---|---|---|---|---|---|---|
| **RQ-0** (context improves multi-step detection vs per-action assessment) | [P1] §III.C, §V.B, Tables I–II (LLM monitor 27/27 false alarms on distributed negatives; stateful firewall 72/72, post hoc); [P2] §3.4 (history-aware `x_k`, proposal only) | FR-POL-01…06, FR-STA-01…03, FR-MON-01…06, FR-EXP-01…09 | C2, C3, C4, C10, C11 | `firewall.state`, `firewall.policy`, `firewall.cascade`, `experiments` | T-EXP-002, T-EXP-004, T-EXP-008 | M-ADR, M-APR, M-FPR-T, M-LTS, M-LAT | VERIFIED |
| **RQ-1** (state vs transcript vs hybrid; cost; robustness) | [P1] §VII, §IX.B (hybrid proposed, not evaluated); [P3] §VI.C (cost vs latency); [P2] §5.1 (planned baseline set) | as RQ-0 + FR-MON-02, FR-EXP-03, FR-EXP-06 | C2, C3, C4, C11 | as above + `experiments.stats` | T-EXP-003, T-EXP-006 | all of `03` §8 | VERIFIED |
| **H1** history necessity (manipulation check) | [P1] §III.D "Action D Invariance" | FR-EXP-02, FR-EXP-04, FR-EXP-07 | C10, C11 | `experiments.generator`, `…metrics` | T-EXP-002, T-EXP-004, T-EXP-007 | Youden `J` on `Ω_crit` (`03` §10.2) | VERIFIED |
| **H2** B6 vs B5 on in-grammar history-dependent scenarios | [P1] Tables I, II, IV (circularity caveat §X); [P1] §VII.B (policy-prior conflict) | FR-POL-06, FR-STA-01…03, FR-MON-02 (`Transcript`), FR-EXP-03, FR-EXP-05, FR-EXP-06, FR-EXP-08 | C2, C3, C4, C11 | `firewall.policy`, `firewall.state`, `firewall.monitor.transcript`, `experiments.evaluate` | T-POL-005, T-STA-003, T-MON-001, T-EXP-005, T-EXP-006 | M-APR(ρ), M-LTS(ρ), M-REVR | VERIFIED |
| **H3** hybrid robustness under perturbation | [P1] §IX.B (hybrid proposal); [P3] §IV (tiering idea); [P2] §3 (deterministic floor + context assessment) | FR-MON-02 (`Hybrid`), FR-MON-04, FR-STA-04, FR-EXP-01 (PRT families) | C3, C4, C9, C10 | `firewall.cascade`, `firewall.policy`, `firewall.tools_sim` | T-MON-003, T-MON-004, T-STA-006 | M-UAR(ρ), M-REVR | VERIFIED |
| **H4** safety floor | [P2] §3.3 (non-compensatory overrides); [P1] §IV (REVIEW on missing evidence); [P4] §III (`T_min` floor) | SEC-01…12, FR-DEC-01, FR-EXE-01…03, FR-REV-01…04 | C1, C3, C5, C6, C8 | `firewall.core`, `firewall.decision`, `firewall.tokens`, `firewall.review` | T-INV-01…12, T-DEC-001 | invariant pass rate; fuzz violations = 0 | VERIFIED |
| **H5** cost / latency | [P3] §V–VI (latency, deep-call reduction, Eq. 6 model) | NFR-02, NFR-09, FR-AUD-02 | C1, C7 | `firewall.core` (timings), `firewall.audit` | T-NFR-002, T-AUD-002 | M-LAT (p50/p95/p99), `f_mon` | VERIFIED (Arm-level) |

---

## 2. Paper evidence → requirements (what each paper contributes)

| Paper evidence | Requirement(s) it motivates | Adopted / modified / rejected |
|---|---|---|
| [P1] Action D Invariance, matched filler | FR-EXP-01, FR-EXP-02 | Adopted |
| [P1] REVIEW on missing/conflicting evidence | FR-POL-03, FR-DEC-01, EVD-01/02 | Adopted |
| [P1] FSM over parsed text | FR-STA-01, FR-STA-02 | **Modified**: typed events; text-parsing kept only as ablation A-01 (`R-05`) |
| [P1] LLM transcript monitor | FR-MON-02 (`Transcript`) | Adopted as comparator under equal-effort rule |
| [P1] Wilson intervals, metrics from saved records | FR-EXP-04, FR-EXP-06 | Adopted, plus cluster bootstrap |
| [P2] Deterministic Layer 0 | FR-POL-01…06 | Adopted |
| [P2] Non-compensatory overrides | SEC-03, SEC-11, FR-DEC-01 | Adopted as properties P-PROHIBIT, P-MONO |
| [P2] CSI/GDS/AVTM, composite `R`, TRANSFORM | — | Deferred (`R-03`, `OQ-17`) |
| [P2] Planned evaluation hygiene (dev/test, paired, repeated LLM runs) | FR-EXP-05, FR-EXP-06, `06` §9 | Adopted |
| [P3] Tiering; raw/parsed/final separation; error policy | FR-MON-04, FR-MON-05 | Adopted (tiering optional for hybrid cost control) |
| [P3] Early-acceptance routing | — | Rejected (`R-02`) |
| [P3] Zero-event upper bound; latency model | FR-EXP-06, NFR-02 | Adopted |
| [P4] Review capacity as a finite resource; `T_min` | FR-REV-01…04, `MR` configuration, M-REVR | Adopted as measurement only |
| [P4] CCS, adaptive thresholds, self-reflection | — | Rejected for MVP (`R-01`, `R-08`) |

---

## 3. Security invariants → requirements → components → tests

| Invariant | Requirement | Components | Modules | Tests | Status |
|---|---|---|---|---|---|
| INV-01 Complete mediation | SEC-01, FR-GW-05 | C1, C6 | `firewall.core`, `firewall.executor` | `test_security_console:test_09` | VERIFIED |
| INV-02 Decision–action binding | SEC-02, FR-EXE-01 | C1, C6 | `firewall.tokens`, `firewall.contracts` | `test_security_invariants_contracts` | VERIFIED |
| INV-03 Hard-prohibition supremacy | SEC-03, FR-DEC-01 | C3, C5 | `firewall.policy`, `firewall.decision` | `test_decision:test_p_prohib_always_denies` | VERIFIED |
| INV-04 Fail-closed | SEC-04, FR-MON-04 | C1…C8 | all | `test_cascade_integration`, `test_invariants_state` | VERIFIED |
| INV-05 REVIEW non-authorization | SEC-05, FR-REV-01, FR-REV-03 | C5, C8 | `firewall.review` | `test_firewall_core:test_12`, console tests | VERIFIED |
| INV-06 Single-use authorization | SEC-06, FR-EXE-02 | C6 | `firewall.tokens`, `firewall.executor` | `test_firewall_core:test_10, 11` | VERIFIED |
| INV-07 Evidence provenance | SEC-07, FR-STA-02 | C2 | `firewall.state` | `test_security_invariants_state:test_inv_07` | VERIFIED |
| INV-08 Label and test isolation | SEC-08, FR-STA-05, FR-MON-06, FR-AUD-03 | C2, C4, C7 | `firewall.cascade.monitor_view`, `experiments` | `test_information_barrier`, `test_label_oracle` | VERIFIED |
| INV-09 Audit completeness and tamper evidence | SEC-09, FR-AUD-01 | C7 | `firewall.audit` | `test_audit:test_audit_store_append_and_verify` | VERIFIED |
| INV-10 Versioned decisions | SEC-10, FR-AUD-02, FR-POL-04 | C1, C7, C9 | `firewall.audit`, `firewall.policy` | `test_information_barrier`, `test_firewall_core` | VERIFIED |
| INV-11 Monotone strictness | SEC-11, FR-DEC-01 | C5 | `firewall.decision` | `test_decision:test_monotone_strictness` | VERIFIED |
| INV-12 Deterministic core | SEC-12, FR-STA-01, NFR-01 | C2, C3, C5 | `firewall.state`, `firewall.policy`, `firewall.decision` | `test_security_invariants_state:test_inv_12` | VERIFIED |

---

## 4. Threat scenarios → families → invariants → tests/metrics

| Threat | Scenario family | Expected behaviour (`B6`) | Invariants | Tests / metrics | Status |
|---|---|---|---|---|---|
| TS-01 | ATK-01 | DENY | INV-03 | `test_cascade_integration`; M-APR | VERIFIED |
| TS-02 | ATK-02 | DENY at completing action | INV-03, INV-07 | `test_cascade_integration`; M-APR | VERIFIED |
| TS-03 | ATK-03 | DENY | INV-03 | `test_cascade_integration` | VERIFIED |
| TS-04 | ATK-04 | DENY, length-invariant | INV-03 | `test_action_d_invariance`; M-APR | VERIFIED |
| TS-05 | ATK-05 | DENY; state unchanged | INV-07 | `test_security_invariants_state:test_inv_07` | VERIFIED |
| TS-06 | ATK-06 | DENY (R4) | INV-03 | `test_firewall_core:test_02` | VERIFIED |
| TS-07 | ATK-07 | DENY/REVIEW at limit | INV-03 | `test_state_engine` | VERIFIED |
| TS-08 | ATK-08 | DENY via registry zone | INV-03, INV-07 | `test_cascade_integration` | VERIFIED |
| TS-09 | ATK-09 (stretch) | DENY via label propagation | INV-03 | deferred to future work | DEFERRED |
| TS-10 | ATK-10 | DENY; LLM-arm failure measured | INV-03, INV-04 | `test_decision:test_inv_03` | VERIFIED |
| TS-11 | EVD-05, EVD-06 | REVIEW/DENY, never ALLOW | INV-04 | `test_cascade_integration:test_05` | VERIFIED |
| TS-12 | invariant tests | executor refuses | INV-02, INV-06 | `test_firewall_core:test_09, 10` | VERIFIED |
| TS-13 | benign review burden | measured | INV-05 | `FINAL_BENCHMARK_REPORT.md` (M-REVR) | VERIFIED |
| TS-14 | invariant tests | impossible by `A-01` | INV-01 | `test_security_console:test_09` | VERIFIED |

Benign lookalikes `BEN-01…09` trace to `M-FPR-T`, `M-LTS(ρ)`, `M-REVR` for each arm (`NYC`).

---

## 5. Component → module → owner → phase

| Component | Module path (`src/firewall/…`) | Provisional owner | Phase | Status |
|---|---|---|---|---|
| Contracts (shared) | `contracts/` | all four (CODEOWNERS) | 1 | VERIFIED |
| C1 Gateway | `core.py` | Akshat | 3 | VERIFIED |
| C2 State builder | `state/` | Shrishti | 4 | VERIFIED |
| C3 Policy engine | `policy/` | Karishma | 2 | VERIFIED |
| C9 Registry | `state/registry.py` | Karishma | 2 | VERIFIED |
| C5 Decision function | `decision/` | Karishma + Akshat | 3 | VERIFIED |
| C6 Executor | `executor/`, `tokens/` | Akshat | 3 | VERIFIED |
| C8 Review service | `review/` | Snehal | 3 | VERIFIED |
| C7 Audit store | `audit/` | Snehal | 4 | VERIFIED |
| C10 Simulated tools | `tools/` | Akshat (tools), Snehal (fixtures) | 5 | VERIFIED |
| C11 Experiment runner | `experiments/` | Shrishti (runner/metrics); Akshat + Snehal (TEST specs) | 5–8 | VERIFIED |
| C4 Monitors | `monitor/`, `cascade/` | Shrishti | 6–7 | VERIFIED |
| FastAPI adapter | `console/` | Akshat | 3 / Console | VERIFIED |
| Dashboard / UI | `console/static/` | Snehal | 9 | OPERATIONAL (Local Web Console) |

---

## 5b. Complete functional-requirement index

Every `FR-*` of `04` with its component, module and tests (all `NYC`). Metric column: the `03` §8 metric the requirement supports, if any.

| Requirement | Component | Module (`src/fw/…`) | Tests | Metric |
|---|---|---|---|---|
| FR-GW-01 | C1 | `gateway/` | T-GW-001 | — |
| FR-GW-02 | C1 | `gateway/`, `contracts/` | T-GW-002, T-GW-006 | — |
| FR-GW-03 | C1 | `gateway/` | T-GW-003 | — |
| FR-GW-04 | C1 | `gateway/` | T-GW-004 | — |
| FR-GW-05 | C1 | `core.py` | T-GW-005, T-INV-01 | M-APR |
| FR-GW-06 | C1 | `api/` | T-API-001…003 | — |
| FR-STA-01 | C2 | `state/` | T-STA-001, T-INV-12 | — |
| FR-STA-02 | C2 | `state/` | T-STA-002, T-INV-07 | M-APR (ATK-05) |
| FR-STA-03 | C2 | `state/` | T-STA-003, T-STA-004 | M-APR (ATK-07) |
| FR-STA-04 | C2 | `state/` | T-STA-006 | — |
| FR-STA-05 | C2 | `state/views.py` | T-STA-005, T-INV-08 | — |
| FR-POL-01…05 | C3 | `policy/` | T-POL-001…007 | — |
| FR-POL-06 | C3 | `policy/`, `config/policy_*.yaml` | T-POL-005 | M-APR, M-FPR-T |
| FR-REG-01 | C9 | `policy/registry.py` | T-POL-006 | — |
| FR-MON-01…02 | C4 | `monitors/` | T-MON-001, T-MON-002 | all arms |
| FR-MON-03 | C4 | `monitors/base.py`, `decision/` | T-MON-006 | — |
| FR-MON-04 | C4 | `monitors/` | T-MON-003, T-MON-004, T-INV-04 | M-REVR |
| FR-MON-05 | C4, C7 | `monitors/`, `audit/` | T-MON-005 | — |
| FR-MON-06 | C4 | `monitors/`, `state/views.py` | T-MON-007, T-INV-08 | — |
| FR-DEC-01…03 | C5 | `decision/` | T-DEC-001…003, T-INV-03, T-INV-11 | — |
| FR-EXE-01…03 | C6 | `executor/` | T-EXE-001…004, T-INV-02, T-INV-06 | — |
| FR-EXE-04 | C6 | `executor/` | T-EXE-005 | — |
| FR-AUD-01…04 | C7 | `audit/`, `labels/` | T-AUD-001…004, T-INV-09, T-INV-10 | M-LAT |
| FR-REV-01…04 | C8 | `review/` | T-REV-001…005, T-INV-05 | M-REVR, M-REV-OUT |
| FR-REV-05, FR-DASH-01 | — | deferred | — | — |
| FR-EXP-01…09 | C10, C11 | `experiments/`, `tools_sim/` | T-EXP-001…009 | all of `03` §8 |

---

## 6. Coverage checks to run during the consistency audit

1. Every `FR-*`, `SEC-*`, `NFR-*` in `04` appears in a row here or in §3; every test ID in `05` §13 is referenced by a requirement.
2. Every hypothesis has a metric and a pre-registered primary outcome (`06` §8.1).
3. Every invariant has a requirement, a component and a test.
4. No component in `02` lacks an owner and a phase.
5. Every `ASSUMED`/`OPEN` item referenced in `00`–`06` is defined in `09`.

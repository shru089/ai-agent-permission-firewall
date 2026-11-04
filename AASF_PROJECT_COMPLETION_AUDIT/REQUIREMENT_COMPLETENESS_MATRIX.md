# Requirement Completeness Matrix

Status meanings: **Completed and tested** = implementation exists and relevant tests were present and full local suite passed; **Implemented, evidence limited** = source exists but coverage/evaluation is incomplete; **Partially implemented** = material planned behavior absent or only a subset exists; **Planned/deferred** = documents explicitly defer it; **Not established** = repository evidence does not support completion.

| Area | Repository evidence | Status | Submission caveat / remaining work |
|---|---|---|---|
| Action contracts and validation | `src/firewall/contracts/`; gateway validation in `src/firewall/core.py`; tests under `tests/unit/` and `tests/security/` | Completed and tested for exercised contracts | No authentication identity should be inferred from a valid request object alone. |
| Firewall orchestration | `firewall.core.FirewallCore.submit`, `resolve_review` in `src/firewall/core.py`; `demo_firewall.py`; core tests | Completed and tested in-process | Demo is a smoke path, not a production deployment or all-tools integration. |
| Policy evaluation | `src/firewall/policy/`; policy tests in `tests/unit/` and `tests/security/` | Completed and tested for configured rules | Scope policy claims to actual configured registry/rules and test cases. |
| State/session updates | `src/firewall/state/`; state/security tests | Completed and tested for modeled typed state | Not evidence of arbitrary data lineage or external session persistence. |
| Semantic monitor interfaces and mock clients | `src/firewall/monitors/`; monitor tests; `experiments/evaluate.py` | Implemented, evidence limited | Mock/model-client behavior does not establish deployed LLM quality or provider behavior. |
| Cascade routing | `src/firewall/cascade/`; route traces in audit; evaluation code | Implemented, evaluation evidence incomplete | H5 lacks cascade-invoked latency distribution and timeout evidence. |
| Human review | `src/firewall/oversight/`, review resolution in `FirewallCore.resolve_review`; tests | Implemented and tested for modeled review flow | Reported rate reduction is split/arm/comparator-specific; not a universal operational savings guarantee. |
| Execution enforcement and authorization tokens | `src/firewall/executor/`, token store modules, core integration; executor/security tests | Implemented and tested in repository model | Token mechanics should be described accurately; token identifiers are server-side stateful single-use records. HMAC-SHA256 is used for evidence receipts, not necessarily to sign the token itself. |
| Audit records and chain | `src/firewall/audit/`; `demo_firewall.py`; audit tests | Implemented and tested for in-process store behavior | Do not imply durable external storage or tamper-proofing against an attacker controlling the process/storage. |
| Credentials and monitor views | `src/firewall/monitors/` and view/redaction code; tests | Implemented for modeled fields, with limits | State exact redaction boundary; do not claim all secrets are universally scrubbed. |
| Canonical experiment evaluator | `experiments/evaluate.py`, `experiments/run_experiment.py`, metrics/statistics modules | Implemented; artifact-backed results exist | Ensure final report values map to exact split, arm, comparator, and preregistered metric. |
| DEV/CAL/TEST-IN/TEST-NOVEL datasets | `experiments/datasets/{dev,cal,test-in,test-novel}/` and manifests | Present; manifest integrity exercised by passing tests | Counts are small (32/8/8/4 traces). Do not generalize to production populations. |
| H1 manipulation check | `experiments/datasets/dev/h1_manipulation_check.json`; `experiments/reports/H1_manipulation_check.md` | Reported DEV result, supported within mock/artifact scope | State exact DEV scope and mock evaluation; avoid live stochastic inference. |
| H2 | `docs/prereg/PREREG-001.md`; `experiments/reports/FINAL_BENCHMARK_REPORT.md` | Not established against frozen criterion | Reconcile LTS versus LTS-0 and report values by split/arm/comparator, or mark unverified. |
| H3 | Frozen preregistration and final benchmark summary | Partially supported by point estimates; full criterion not established | Provide preregistered unsafe-allowance confidence bound or mark unverified. |
| H4 | Policy/executor invariant code/tests and benchmark summary | Tested invariant plus bounded observed result | Keep test evidence distinct from finite dataset empirical rates. |
| H5 latency | `docs/prereg/PREREG-001.md`, `experiments/reports/FINAL_BENCHMARK_REPORT.md`, `experiments/reports/DEV_monitors_benchmark.md` | NOT VERIFIED | Missing cascade-invoked p95 and hard-timeout evidence; DEV summary/detail mismatch. |
| Synthetic latency benchmark | `experiments/benchmark_latency.py` and tests | Implemented and tested as a microbenchmark | Not the canonical evaluator and not evidence for H5. |
| Dashboard/review UI | `src/firewall/dashboard/`; deferred items in `docs/04_PRD.md` §8 and `docs/08_IMPLEMENTATION_ROADMAP.md` Phase 9 | Partially implemented / UI deferred | CLI/HTML/report helper presence does not prove an integrated interactive UI. |
| External API/authentication and real tools | Requirements in `docs/04_PRD.md` §4.1; non-goals/deferred sections | Planned/deferred or partial | Do not claim complete production authentication or real-world integrations. |
| Coverage target | `docs/04_PRD.md` NFR-04 | Proposed only | No coverage report/result was produced by the required commands. Remove coverage achievement claims. |
| Publication, similarity, Turnitin | No supporting repository artifact identified | Not established | Omit publication-readiness, acceptance, similarity, and Turnitin claims. |
| CI/release readiness | `.github/workflows/ci.yml`, local checks | Limited local verification | The specified local commands do not establish remote CI or reviewer status. |

## Test evidence categories

The test tree includes unit and security-focused tests, plus experiment/evaluation and artifact-integrity tests under `tests/`. The requested test run reports **433 passed**. Exact individual case counts by category were not independently collected; avoid inventing category totals. Representative security cases are mapped by names and paths in [TEST_AND_QUALITY_STATUS.md](TEST_AND_QUALITY_STATUS.md). The suite result alone does not make every planned acceptance criterion complete; see stale IDs in `docs/07_REQUIREMENTS_TRACEABILITY.md`.

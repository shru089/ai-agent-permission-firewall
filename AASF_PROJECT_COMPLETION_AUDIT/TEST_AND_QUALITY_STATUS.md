# Test and Quality Status

## Commands run and outcomes

| Command | Result | Scope / limitation |
|---|---|---|
| `.venv/bin/python -m pytest -q` | **433 passed**, exit 0 | Current checked-out test suite only. |
| `.venv/bin/python -m mypy src tests` | **Success: no issues found in 82 source files**, exit 0 | Type checking for these paths. |
| `.venv/bin/python -m ruff check experiments/benchmark_latency.py tests/unit/test_benchmark_latency.py src tests experiments` | **All checks passed**, exit 0 | Requested Ruff scope; not repository-wide. |
| `.venv/bin/python demo_firewall.py` | exit 0 | Smoke demo produced ALLOW and DENY and valid audit chains. |

Full captured output: [commands_and_outputs.md](evidence/commands_and_outputs.md).

## Test categories and evidence

The repository contains test modules under `tests/unit/`, `tests/security/`, `tests/experiments/`, and other `tests/` subtrees. The full run counted 433 tests total. No per-category test totals were generated, so none are asserted here.

Representative evidence areas:

- **Policy / decision behavior:** `tests/unit/` policy and decision modules; corresponding implementation in `src/firewall/policy/` and `src/firewall/decision/`.
- **State and session semantics:** `src/firewall/state/` and state-focused tests under `tests/unit/` / `tests/security/`.
- **Monitor errors and interfaces:** `src/firewall/monitors/` and monitor tests, including malformed/unknown/error paths where represented.
- **Executor and review invariants:** `src/firewall/executor/`, `src/firewall/oversight/`, and security/unit tests.
- **Audit integrity:** `src/firewall/audit/`, audit tests, and `demo_firewall.py` showing valid chain output for two requests.
- **Dataset / manifest integrity:** `tests/experiments/test_manifest.py`, including checksum, held-out split and commitment tests.
- **Benchmark code:** `tests/unit/test_benchmark_latency.py` covers the synthetic benchmark implementation; it does not convert that microbenchmark into canonical evaluator evidence.

Named invariant/test IDs in design documents are documented in `docs/05_TECHNICAL_SPEC.md` §13 and mapped by `docs/07_REQUIREMENTS_TRACEABILITY.md`; however, that traceability file still marks tests NYC. Treat the test source and actual run as evidence, not stale status cells. Test names and exact mappings should be checked against current files before being reproduced in the final report.

## Missing or unverified test evidence

- No coverage percentage was measured; NFR-04 in `docs/04_PRD.md` is a proposed coverage target.
- Passing tests do not prove production security, resistance to arbitrary attackers, or provider/model behavior.
- No dedicated validation was run here for the H5 cascade-invoked p95/hard-timeout criteria.
- No full report build, PDF export, external CI run, or publication/similarity service check was run as part of this audit.

## Reproduction commands

Run all local tests: `.venv/bin/python -m pytest -q`.

Run manifest integrity tests: `.venv/bin/python -m pytest -q tests/experiments/test_manifest.py`.

Run synthetic latency benchmark tests: `.venv/bin/python -m pytest -q tests/unit/test_benchmark_latency.py`.

The individual paths above are repository paths; run them from the repository root.

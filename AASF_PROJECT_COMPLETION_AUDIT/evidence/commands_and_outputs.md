# Commands and Outputs

Captured during the audit in `/Users/akshatkasurde/ai-agent-permission-firewall`, 2026-11-04. These are the exact requested verification commands and terminal output. No report build or evaluation run was performed.

## `.venv/bin/python -m pytest -q`

```text
........................................................................ [ 16%]
........................................................................ [ 33%]
........................................................................ [ 49%]
........................................................................ [ 66%]
........................................................................ [ 83%]
........................................................................ [ 99%]
.                                                                        [100%]
433 passed in 1.23s
exit_code=0
```

## `.venv/bin/python -m mypy src tests`

```text
Success: no issues found in 82 source files
exit_code=0
```

## `.venv/bin/python -m ruff check experiments/benchmark_latency.py tests/unit/test_benchmark_latency.py src tests experiments`

```text
All checks passed!
exit_code=0
```

## `.venv/bin/python demo_firewall.py`

```text
=== Permitted action ===
Request:
  session_id: demo-allow
  tool:       validate_schema
  arguments:  {}
Firewall decision:
  decision:       ALLOW
  status:         EXECUTED
  policy verdict: PERMIT
  monitor verdict: NOT_CONSULTED
  reason codes:   ['POLICY_PERMIT:P-filler-read-low']
  route path:     fast_path
  monitor called: False
Audit records:
  DECISION: decision=ALLOW, policy_verdict=PERMIT, monitor_verdict=NOT_CONSULTED, reason_codes=['POLICY_PERMIT:P-filler-read-low']
  ROUTE_TRACE: path=fast_path, final_decision=ALLOW, monitor_invoked=False, reason_codes=['POLICY_PERMIT:P-filler-read-low']
  audit chain valid: True

=== Prohibited action ===
Request:
  session_id: demo-deny
  tool:       relabel_resource
  arguments:  {'resource_ref': 'customer_records', 'classification': 'PUBLIC'}
Firewall decision:
  decision:       DENY
  status:         DENIED
  policy verdict: PROHIBIT
  monitor verdict: NOT_CONSULTED
  reason codes:   ['POLICY_PROHIBIT:R4-agents-cannot-relabel']
  route path:     fast_path
  monitor called: False
Audit records:
  DECISION: decision=DENY, policy_verdict=PROHIBIT, monitor_verdict=NOT_CONSULTED, reason_codes=['POLICY_PROHIBIT:R4-agents-cannot-relabel']
  ROUTE_TRACE: path=fast_path, final_decision=DENY, monitor_invoked=False, reason_codes=['POLICY_PROHIBIT:R4-agents-cannot-relabel']
  audit chain valid: True

Demo completed successfully.
exit_code=0
```

## Initial repository state

```text
Branch: integrate/main-into-ci-ruff-lint-scope
HEAD: 2a40bdb Add firewall decision-path demonstration
Pre-existing modified paths:
  AASF_FINAL_PROJECT_REPORT/AASF_FINAL_PROJECT_REPORT.docx
  AASF_FINAL_PROJECT_REPORT/generate_charts.py
  AASF_FINAL_PROJECT_REPORT/generate_report.py
  experiments/reports/FINAL_BENCHMARK_REPORT.md
  scratch/report_builder/chapter1.py
  scratch/report_builder/chapter2.py
  scratch/report_builder/chapter3.py
  scratch/report_builder/chapter4.py
  scratch/report_builder/chapter5.py
  scratch/report_builder/chapter6.py
  scratch/report_builder/chapter7.py
  scratch/report_builder/chapter8.py
  scratch/report_builder/chapter9_and_backmatter.py
  scratch/report_builder/front_matter.py
Pre-existing untracked path: notes/
```

No pre-existing changes above were modified by this audit. The only intended new files are this audit directory and its contents. No commit or push was performed.

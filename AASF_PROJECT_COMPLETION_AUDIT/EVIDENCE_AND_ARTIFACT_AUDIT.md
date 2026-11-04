# Evidence and Artifact Audit

## Dataset splits

The four split directories are under `experiments/datasets/`:

| Split | Trace file | Labels file | Traces | Manifest |
|---|---|---|---:|---|
| DEV | `experiments/datasets/dev/traces.jsonl` | `experiments/datasets/dev/labels.jsonl` | 32 | `experiments/datasets/dev/manifest.json` |
| CAL | `experiments/datasets/cal/traces.jsonl` | `experiments/datasets/cal/labels.jsonl` | 8 | `experiments/datasets/cal/manifest.json` |
| TEST-IN | `experiments/datasets/test-in/traces.jsonl` | `experiments/datasets/test-in/labels.jsonl` | 8 | `experiments/datasets/test-in/manifest.json` |
| TEST-NOVEL | `experiments/datasets/test-novel/traces.jsonl` | `experiments/datasets/test-novel/labels.jsonl` | 4 | `experiments/datasets/test-novel/manifest.json` |

The manifest test module `tests/experiments/test_manifest.py` contains `test_manifest_checksums_match_all_files`, `test_held_out_splits_manifest_integrity`, `test_test_commitment_integrity`, and `test_no_cal_or_test_traces_in_dev_package`. The full test command passed, so these assertions passed in this checkout. Preregistration commitment is `docs/prereg/TEST_COMMITMENT.sha256`. See [artifact_inventory.md](evidence/artifact_inventory.md).

## Evaluation and H1 evidence

- Evaluator entry points: `experiments/evaluate.py` and `experiments/run_experiment.py`.
- Final reported metrics: `experiments/reports/FINAL_BENCHMARK_REPORT.md`.
- H1 specific artifacts: `experiments/datasets/dev/h1_manipulation_check.json` and `experiments/reports/H1_manipulation_check.md`.
- Detailed DEV monitor metrics: `experiments/reports/DEV_monitors_benchmark.md`.
- Frozen thresholds/method: `docs/prereg/PREREG-001.md`; general protocol: `docs/06_EXPERIMENT_PROTOCOL.md`.

The DEV H1 artifact reports B3 Youden J = 0 and the B4 mock result with a 95% cluster-bootstrap interval `[0,0]` (1,000 resamples). Treat it as a DEV manipulation-check result under the recorded mock configuration, not as evidence about a live stochastic model. The final benchmark report states held-out values; do not conflate those with the DEV H1 artifact.

The frozen H2 criterion requires an APR comparison and B6 LTS at least 0.10 above B5. The report foregrounds LTS-0, a distinct measure; listed LTS values do not establish that criterion. H3 requires a review reduction and a one-sided 95% upper bound on unsafe-allowance increase; the final summary shows point values but not that bound. These are evidence gaps, not proof of failure.

H5 is **NOT VERIFIED** from current canonical artifacts. The final summary reports P1 arm-level p95 1.023 ms TEST-IN and 0.936 ms TEST-NOVEL; cascade-invoked p95 and the 1,500 ms hard-timeout criterion are absent. DEV P1 p95 differs: 0.878 ms in the final summary versus 4.774 ms in `DEV_monitors_benchmark.md`. `experiments/benchmark_latency.py` is a synthetic-request microbenchmark and must remain separate from canonical evaluator measurements.

## Artifact and report provenance

The report files and report-source edits were already modified in the worktree at audit start. The audit therefore identifies their state but does not treat those modifications as committed or as an approved final artifact. Current report sources include `AASF_FINAL_PROJECT_REPORT/generate_report.py`, `AASF_FINAL_PROJECT_REPORT/generate_charts.py`, and `scratch/report_builder/*.py`; the benchmark narrative is `experiments/reports/FINAL_BENCHMARK_REPORT.md`.

The final benchmark report has an uncommitted diff: its lead sentence now says H5 is not verified, and its H5 row is marked NOT VERIFIED, but detailed H1-H4 rows/paragraphs still use CONFIRMED. In the report-generation source, residual 415-test statements remain in `AASF_FINAL_PROJECT_REPORT/generate_report.py` (around lines 648 and 785 in this checkout). `scratch/report_builder` text was edited to use 433 in some sections. Choose one authoritative source, reconcile all text, then generate a final artifact only when authorized. This audit did not run a report build.

No PDF generation or publication/Turnitin evidence was established by the commands in this audit. No test-coverage command or coverage artifact was run/found for this audit.

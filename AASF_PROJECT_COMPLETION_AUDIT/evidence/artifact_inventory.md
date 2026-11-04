# Artifact Inventory

Repository-relative paths below were inspected in this checkout. Counts are from the JSONL files; manifest verification evidence is the passing integrity tests listed below.

## Canonical split artifacts

| Split | Trace count | Key files |
|---|---:|---|
| DEV | 32 | `experiments/datasets/dev/traces.jsonl`, `labels.jsonl`, `manifest.json`, `README.md`, `h1_manipulation_check.json` |
| CAL | 8 | `experiments/datasets/cal/traces.jsonl`, `labels.jsonl`, `manifest.json`, `README.md` |
| TEST-IN | 8 | `experiments/datasets/test-in/traces.jsonl`, `labels.jsonl`, `manifest.json`, `README.md` |
| TEST-NOVEL | 4 | `experiments/datasets/test-novel/traces.jsonl`, `labels.jsonl`, `manifest.json`, `README.md` |

All four split directories also contain provenance / label audit and split-isolation documentation files. Commitment file: `docs/prereg/TEST_COMMITMENT.sha256`.

Manifest integrity tests in `tests/experiments/test_manifest.py`:

- `test_manifest_checksums_match_all_files`
- `test_held_out_splits_manifest_integrity`
- `test_test_commitment_integrity`
- `test_no_cal_or_test_traces_in_dev_package`

All were included in the successful full pytest run (433 passed).

## Protocol and evaluation artifacts

- Frozen protocol / thresholds: `docs/prereg/PREREG-001.md`.
- General experiment protocol: `docs/06_EXPERIMENT_PROTOCOL.md`.
- H1 machine-readable output: `experiments/datasets/dev/h1_manipulation_check.json`.
- H1 report: `experiments/reports/H1_manipulation_check.md`.
- Final split summary: `experiments/reports/FINAL_BENCHMARK_REPORT.md`.
- DEV monitor report: `experiments/reports/DEV_monitors_benchmark.md`.
- Evaluator code: `experiments/evaluate.py`, `experiments/run_experiment.py`.
- Synthetic microbenchmark: `experiments/benchmark_latency.py`; unit tests: `tests/unit/test_benchmark_latency.py`.

The exploratory CSV files under `experiments/results/` are not the same thing as the canonical split/arm summary and should not be substituted for it without verifying their schema/provenance.

## Report sources and current worktree caveat

- `AASF_FINAL_PROJECT_REPORT/generate_report.py`
- `AASF_FINAL_PROJECT_REPORT/generate_charts.py`
- `scratch/report_builder/*.py`
- `experiments/reports/FINAL_BENCHMARK_REPORT.md`
- Generated DOCX: `AASF_FINAL_PROJECT_REPORT/AASF_FINAL_PROJECT_REPORT.docx`

These included pre-existing uncommitted modifications at audit start. The report sources disagree in places; the DOCX was not rebuilt in this audit. No PDF artifact or completed PDF export was established here. The source chart labels in the edited chart script do not by themselves establish that the chart is embedded in the currently generated DOCX.

## Repository code and test layout

- Runtime package: `src/firewall/`.
- Legacy/duplicate trees: `src/fw/`, `legacy/` (active-source imports from these were not found).
- Tests: `tests/unit/`, `tests/security/`, `tests/experiments/`, and other `tests/` paths.
- Demo: `demo_firewall.py`.

This inventory does not list artifact hashes because no separate inventory hashing command was part of the specified verification sequence.

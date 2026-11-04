# Pending report-text edits

The approved report-text corrections could not be applied on
`fix/ci-ruff-lint-scope` because the report-generation sources are absent:

- `AASF_FINAL_PROJECT_REPORT/generate_report.py`
- `scratch/report_builder/*.py`

These sources exist on `origin/main` at `4481a9e`, which is ahead of this branch.

Do not add report-generation sources to the CI branch. Apply the text-only
edits on a separate report branch or worktree containing those sources.

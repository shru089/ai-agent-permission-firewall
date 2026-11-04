# Remaining Work Plan

## P0 — Submission blockers

1. **Reconcile hypothesis status with frozen preregistration.** Use `docs/prereg/PREREG-001.md` as the controlling criterion. For H2, report LTS (not LTS-0) by split and comparison or mark H2 not verified. For H3, provide the preregistered one-sided 95% upper bound on unsafe-allowance increase or mark H3 not verified. Do not label all H1–H4 “confirmed” unless each full criterion is evidenced.
2. **Keep H5 NOT VERIFIED.** Do not use `experiments/benchmark_latency.py` as H5 evidence. Report the canonical P1 arm-level TEST-IN 1.023 ms and TEST-NOVEL 0.936 ms with caveats; expose the DEV 0.878/4.774 ms discrepancy; state that cascade-invoked p95 and hard-timeout evidence are missing.
3. **Unify final report provenance and wording.** Identify whether `AASF_FINAL_PROJECT_REPORT/generate_report.py` or `scratch/report_builder/*.py` generates the submitted document. Remove stale 415-test wording (actual current requested run: 433 passed), ensure all sections agree, and avoid unverified publication, Turnitin, coverage, production-grade, or absolute-security claims. The current generated DOCX is modified in the worktree and is not proof of a clean reproducible build.
4. **Scope every empirical claim.** Name split, arm, comparator, metric, and denominator/sample size. Distinguish DEV manipulation check from held-out evaluation and mock monitors from real model execution.

## P1 — Correct stale project status

5. Update or label as historical snapshots the status text in `docs/07_REQUIREMENTS_TRACEABILITY.md` and `docs/08_IMPLEMENTATION_ROADMAP.md`; their NYC/not-started statements conflict with actual source/tests.
6. Update the coverage section in any final report to say coverage was not measured in this audit. `docs/04_PRD.md` NFR-04 is a proposed target, not a result.
7. State deferred scope directly: production readiness and real-world integrations are explicit PRD non-goals (`docs/04_PRD.md` §3); dashboard/review UI is deferred in §8.

## P2 — Final verification after authorized corrections

8. Re-run only the exact commands relevant to the changes: pytest, mypy, and the configured Ruff scope already passed in this audit; rerun if source changes affect them. If report text/build sources change, build only the selected report artifact, then inspect the document text and embedded chart media. Do not regenerate evaluation artifacts to fix prose.
9. Archive the final report, exact source revision, command outputs, and artifact hashes according to the institution's actual submission rules. No such institutional rule is inferred here.

## Clarifications for the project team

- Decide whether H2/H3 outcomes should be reported as not verified or whether a permitted, preregistered analysis already exists outside the checked-in artifacts.
- Resolve the DEV latency discrepancy from original canonical output; do not silently choose one value.
- Confirm required deliverables (PDF, source, similarity check) from the course/institution. Repository evidence does not establish those requirements or their completion.

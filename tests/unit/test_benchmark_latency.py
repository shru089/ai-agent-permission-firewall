"""Unit tests for experiments/benchmark_latency.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.benchmark_latency import (
    PATH_AUDIT,
    PATH_FULL,
    PATH_POLICY,
    PATH_POLICY_STATE,
    PATH_POLICY_STATE_MONITOR,
    default_synthetic_items,
    load_work_items,
    main,
    measure_full,
    nearest_rank_percentile,
    parse_args,
    run_benchmark,
    select_item,
    summarize_latencies_ms,
    work_items_from_traces,
)
from experiments.evaluate import Trace, TraceAction, create_default_eval_registry
from firewall.core import FirewallCore
from firewall.policy.evaluator import create_default_stateful_policy


def test_nearest_rank_percentile() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert nearest_rank_percentile(values, 50) == 3.0
    assert nearest_rank_percentile(values, 100) == 5.0
    with pytest.raises(ValueError, match="empty sample"):
        nearest_rank_percentile([], 50)


def test_summarize_latencies_ms() -> None:
    summary = summarize_latencies_ms([1.0, 2.0, 3.0, 4.0, 5.0])
    assert summary.n == 5
    assert summary.min_ms == 1.0
    assert summary.max_ms == 5.0
    assert summary.mean_ms == 3.0
    assert summary.median_ms == summary.p50_ms
    assert summary.stdev_ms > 0.0


def test_summarize_rejects_empty() -> None:
    with pytest.raises(ValueError, match="fabricate"):
        summarize_latencies_ms([])


def test_missing_dataset_errors(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.json"
    with pytest.raises(FileNotFoundError):
        load_work_items(str(missing))


def test_load_work_items_rejects_non_dev_split(tmp_path: Path) -> None:
    traces = [
        {
            "trace_id": "TR_TEST",
            "template_id": "TMP_A",
            "family_id": "ATK-01",
            "scenario_type": "benign",
            "split": "TEST-IN",
            "actions": [
                {"step_index": 0, "tool": "validate_schema", "arguments": {}, "y": 0},
            ],
        }
    ]
    data_file = tmp_path / "held_out.json"
    data_file.write_text(json.dumps(traces), encoding="utf-8")
    with pytest.raises(ValueError, match="non-DEV"):
        load_work_items(str(data_file))


def test_work_items_from_empty_traces_error() -> None:
    empty = Trace(
        trace_id="T0",
        template_id="TMP",
        family_id="F",
        scenario_type="benign",
        actions=[],
        split="DEV",
    )
    with pytest.raises(ValueError, match="no actions"):
        work_items_from_traces([empty])


def test_work_items_use_critical_step() -> None:
    trace = Trace(
        trace_id="T1",
        template_id="TMP",
        family_id="F",
        scenario_type="benign",
        split="DEV",
        critical_step_index=1,
        actions=[
            TraceAction(
                step_index=0,
                tool="select_resource",
                arguments={"resource_ref": "public_records"},
            ),
            TraceAction(step_index=1, tool="validate_schema", arguments={}, is_critical=True),
            TraceAction(step_index=2, tool="execute_export", arguments={}),
        ],
    )
    items = work_items_from_traces([trace])
    assert len(items) == 1
    assert items[0].target.tool == "validate_schema"
    assert len(items[0].prefix) == 1
    assert "y" not in items[0].target.arguments


def test_run_benchmark_small_each_path() -> None:
    items = default_synthetic_items()
    for path in (
        PATH_POLICY,
        PATH_POLICY_STATE,
        PATH_POLICY_STATE_MONITOR,
        PATH_FULL,
        PATH_AUDIT,
    ):
        samples = run_benchmark(path, warmup=1, runs=2, items=items)
        assert len(samples) == 2
        assert all(s >= 0.0 for s in samples)


def test_cli_missing_dataset(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    rc = main(["--dataset", str(missing), "--warmup", "0", "--runs", "1"])
    assert rc == 1


def test_cli_synthetic_full_writes_output(tmp_path: Path) -> None:
    out = tmp_path / "latency.json"
    rc = main(
        [
            "--path",
            "full",
            "--warmup",
            "1",
            "--runs",
            "3",
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["path"] == "full"
    assert payload["n"] == 3
    assert payload["timed_function"] == (
        "FirewallCore.submit through AuditStore.append(ROUTE_TRACE)"
    )
    assert len(payload["samples_ms"]) == 3
    assert "mean_ms" in payload


def test_cli_dataset_traces(tmp_path: Path) -> None:
    traces = [
        {
            "trace_id": "TR_01",
            "template_id": "TMP_A",
            "family_id": "ATK-01",
            "scenario_type": "benign",
            "split": "DEV",
            "critical_step_index": 1,
            "actions": [
                {
                    "step_index": 0,
                    "tool": "select_resource",
                    "arguments": {"resource_ref": "public_records"},
                    "y": 0,
                },
                {
                    "step_index": 1,
                    "tool": "validate_schema",
                    "arguments": {},
                    "y": 0,
                    "is_critical": True,
                },
            ],
        }
    ]
    data_file = tmp_path / "dev.json"
    data_file.write_text(json.dumps(traces), encoding="utf-8")
    rc = main(
        [
            "--dataset",
            str(data_file),
            "--path",
            "policy-state",
            "--warmup",
            "1",
            "--runs",
            "2",
        ]
    )
    assert rc == 0


def test_cli_help_mentions_synthetic_and_not_evaluate(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "synthetic ActionRequests" in help_text
    assert "does not run experiments.evaluate" in help_text
    assert "FirewallCore.submit" in help_text
    assert "ROUTE_TRACE" in help_text


def test_cli_invalid_warmup_rejected() -> None:
    rc = main(["--warmup", "-1", "--runs", "1"])
    assert rc == 1


def test_cli_invalid_runs_rejected() -> None:
    rc = main(["--warmup", "0", "--runs", "0"])
    assert rc == 1


def test_empty_dataset_errors(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="loaded 0 traces"):
        load_work_items(str(empty))
    rc = main(["--dataset", str(empty), "--warmup", "0", "--runs", "1"])
    assert rc == 1


def test_measure_full_missing_route_trace_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    items = default_synthetic_items()
    item = next(i for i in items if i.prefix)
    real_submit = FirewallCore.submit
    prefix_len = len(item.prefix)
    calls = {"n": 0}

    def _submit_skip_measured(self: FirewallCore, request: object) -> object:
        calls["n"] += 1
        if calls["n"] <= prefix_len:
            return real_submit(self, request)  # type: ignore[arg-type]
        return None

    monkeypatch.setattr(FirewallCore, "submit", _submit_skip_measured)
    engine = create_default_stateful_policy()
    registry = create_default_eval_registry()
    with pytest.raises(RuntimeError, match="new decision ROUTE_TRACE"):
        measure_full(engine, registry, item, "bench_missing_route_trace")


def _critical_export_trace() -> Trace:
    return Trace(
        trace_id="T_CRIT",
        template_id="TMP",
        family_id="F",
        scenario_type="attack",
        split="DEV",
        critical_step_index=1,
        actions=[
            TraceAction(
                step_index=0,
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            ),
            TraceAction(
                step_index=1,
                tool="execute_export",
                arguments={},
                is_critical=True,
            ),
            TraceAction(step_index=2, tool="validate_schema", arguments={}),
        ],
    )


def test_dataset_selects_critical_step_action() -> None:
    items = work_items_from_traces([_critical_export_trace()])
    assert items[0].target.tool == "execute_export"
    for path in (PATH_FULL, PATH_POLICY, PATH_POLICY_STATE_MONITOR):
        chosen = select_item(items, path, 0, synthetic=False)
        assert chosen.target.tool == "execute_export", path


def test_synthetic_full_still_prefers_validate_schema() -> None:
    items = default_synthetic_items()
    chosen = select_item(items, PATH_FULL, 0, synthetic=True)
    assert chosen.target.tool == "validate_schema"

"""
CLI latency benchmark for one AASF firewall action decision.

Times the real in-process decision path in FirewallCore / PolicyEngine /
CascadeAdapter / combinator.decide / AuditStore — not pytest, H1 evaluation,
or cluster bootstrap.

Default mode uses synthetic ActionRequests, not DEV/H1 evaluation.
--dataset supplies actions to this benchmark only; it does not run
experiments.evaluate.

experiments.evaluate times the whole FirewallCore.submit call, including
executor work. This CLI's --path full starts immediately before
FirewallCore.submit(target) and stops immediately after the decision
ROUTE_TRACE AuditStore.append, before ReviewService or ControlledExecutor
post-decision work.

Usage:
  python experiments/benchmark_latency.py --warmup 5 --runs 20
  python experiments/benchmark_latency.py --dataset path/to/traces.json --path full
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

_ROOT_DIR = Path(__file__).resolve().parent.parent
_SRC_DIR = _ROOT_DIR / "src"
for _import_dir in (_ROOT_DIR, _SRC_DIR):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from experiments.evaluate import (  # noqa: E402
    Trace,
    create_default_eval_registry,
    load_dataset,
    make_clean_action_request,
)
from experiments.metrics import _percentile  # noqa: E402
from firewall.audit.store import AuditRecord, AuditStore  # noqa: E402
from firewall.cascade.adapter import CascadeAdapter  # noqa: E402
from firewall.contracts.enums import Decision, PolicyVerdict  # noqa: E402
from firewall.contracts.hashing import compute_action_hash  # noqa: E402
from firewall.contracts.models import ActionRequest, CanonicalAction  # noqa: E402
from firewall.core import FirewallCore  # noqa: E402
from firewall.decision.combinator import DecisionConfig, decide  # noqa: E402
from firewall.monitor.base import SafeMonitorWrapper  # noqa: E402
from firewall.monitor.mock import DeterministicMockMonitor  # noqa: E402
from firewall.policy.evaluator import PolicyEngine, create_default_stateful_policy  # noqa: E402
from firewall.state.engine import initial_state  # noqa: E402
from firewall.state.registry import Registry  # noqa: E402
from firewall.state.views import build_monitor_view  # noqa: E402

PATH_POLICY = "policy"
PATH_POLICY_STATE = "policy-state"
PATH_POLICY_STATE_MONITOR = "policy-state-monitor"
PATH_FULL = "full"
PATH_AUDIT = "audit"
BENCHMARK_PATHS = (
    PATH_POLICY,
    PATH_POLICY_STATE,
    PATH_POLICY_STATE_MONITOR,
    PATH_FULL,
    PATH_AUDIT,
)


@dataclass(frozen=True)
class WorkItem:
    """One target action plus untimed prefix used to fold session state."""

    prefix: tuple[ActionRequest, ...]
    target: ActionRequest
    trace_id: Optional[str] = None


@dataclass(frozen=True)
class LatencySummary:
    n: int
    mean_ms: float
    median_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    stdev_ms: float


def nearest_rank_percentile(sorted_values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile; delegates to experiments.metrics._percentile."""
    if not sorted_values:
        raise ValueError("Cannot compute percentile of an empty sample list")
    return _percentile([float(x) for x in sorted_values], pct)


def summarize_latencies_ms(samples_ms: Sequence[float]) -> LatencySummary:
    if not samples_ms:
        raise ValueError("No latency samples recorded; refusing to fabricate results")
    ordered = sorted(float(x) for x in samples_ms)
    n = len(ordered)
    stdev = statistics.stdev(ordered) if n >= 2 else 0.0
    median = nearest_rank_percentile(ordered, 50)
    return LatencySummary(
        n=n,
        mean_ms=float(statistics.mean(ordered)),
        median_ms=median,
        p50_ms=median,
        p95_ms=nearest_rank_percentile(ordered, 95),
        p99_ms=nearest_rank_percentile(ordered, 99),
        min_ms=ordered[0],
        max_ms=ordered[-1],
        stdev_ms=float(stdev),
    )


def canonical_action_from_request(request: ActionRequest, seq: int = 1) -> CanonicalAction:
    action_hash = compute_action_hash(request.session_id, seq, request.tool, request.arguments)
    return CanonicalAction(
        action_id=f"bench_act_{seq}",
        session_id=request.session_id,
        seq=seq,
        tool=request.tool,
        arguments=dict(request.arguments),
        action_hash=action_hash,
    )


def default_synthetic_items() -> list[WorkItem]:
    """
    Built-in ActionRequests using tools from create_default_eval_registry().
    Used only when --dataset is omitted. These are not DEV traces and are not
    fabricated latency numbers.
    """
    prefix = (
        ActionRequest(
            session_id="bench",
            tool="select_resource",
            arguments={"resource_ref": "customer_records"},
        ),
        ActionRequest(
            session_id="bench",
            tool="configure_destination",
            arguments={"destination_ref": "external_storage"},
        ),
    )
    export_target = ActionRequest(session_id="bench", tool="execute_export", arguments={})
    permit_target = ActionRequest(session_id="bench", tool="validate_schema", arguments={})
    return [
        WorkItem(prefix=prefix, target=export_target, trace_id="synthetic_stateful_export"),
        WorkItem(prefix=(), target=permit_target, trace_id="synthetic_permit_read_low"),
    ]


def work_items_from_traces(traces: Sequence[Trace]) -> list[WorkItem]:
    items: list[WorkItem] = []
    for trace in traces:
        if not trace.actions:
            continue
        target_index = len(trace.actions) - 1
        if trace.critical_step_index is not None and 0 <= trace.critical_step_index < len(
            trace.actions
        ):
            target_index = trace.critical_step_index
        prefix_reqs = tuple(
            make_clean_action_request("bench", action) for action in trace.actions[:target_index]
        )
        target_req = make_clean_action_request("bench", trace.actions[target_index])
        items.append(WorkItem(prefix=prefix_reqs, target=target_req, trace_id=trace.trace_id))
    if not items:
        raise ValueError("Dataset traces contain no actions compatible with the evaluator")
    return items


def load_work_items(dataset_path: Optional[str]) -> tuple[list[WorkItem], str]:
    if dataset_path is None:
        return default_synthetic_items(), "synthetic_action_requests"
    traces = load_dataset(split="DEV", dataset_path=dataset_path)
    if not traces:
        raise ValueError(f"Dataset at {dataset_path} loaded 0 traces")
    non_dev_splits = sorted({trace.split for trace in traces if trace.split != "DEV"})
    if non_dev_splits:
        raise ValueError(
            f"Dataset at {dataset_path} contains non-DEV splits: {non_dev_splits}"
        )
    return work_items_from_traces(traces), str(dataset_path)


def _elapsed_ms(start_ns: int, stop_ns: Optional[int] = None) -> float:
    """Convert a perf_counter_ns interval to milliseconds (FirewallCore's unit)."""
    end_ns = time.perf_counter_ns() if stop_ns is None else stop_ns
    return (end_ns - start_ns) / 1_000_000.0


class _DecisionAuditStore(AuditStore):
    """Timestamps the ROUTE_TRACE append performed by FirewallCore._record_decision_audit."""

    def __init__(self) -> None:
        super().__init__()
        self.decision_audit_completed_ns: Optional[int] = None

    def append(
        self,
        session_id: str,
        record_type: str,
        payload: dict[str, Any],
        mono_ns: Optional[int] = None,
    ) -> AuditRecord:
        record = super().append(session_id, record_type, payload, mono_ns)
        if record_type == "ROUTE_TRACE":
            self.decision_audit_completed_ns = time.perf_counter_ns()
        return record


def bind_session(request: ActionRequest, session_id: str) -> ActionRequest:
    return request.model_copy(update={"session_id": session_id})


def make_firewall(
    registry: Registry,
    policy_engine: PolicyEngine,
    *,
    with_monitor: bool,
    audit_store: Optional[AuditStore] = None,
) -> FirewallCore:
    monitor = DeterministicMockMonitor() if with_monitor else None
    cfg = DecisionConfig(monitor_authority="escalate_only") if with_monitor else DecisionConfig()
    return FirewallCore(
        registry=registry,
        policy_engine=policy_engine,
        monitor=monitor,
        decision_config=cfg,
        audit_store=audit_store,
    )


def replay_prefix(fw: FirewallCore, prefix: Sequence[ActionRequest], session_id: str) -> None:
    for req in prefix:
        fw.submit(bind_session(req, session_id))


def measure_policy(
    engine: PolicyEngine,
    registry: Registry,
    item: WorkItem,
    session_id: str,
) -> float:
    """PolicyEngine.evaluate against initial_state (API always requires state)."""
    target = bind_session(item.target, session_id)
    action = canonical_action_from_request(target, seq=1)
    state = initial_state(session_id)
    t0 = time.perf_counter_ns()
    engine.evaluate(action, state, registry)
    return _elapsed_ms(t0)


def measure_policy_state(
    engine: PolicyEngine,
    registry: Registry,
    item: WorkItem,
    session_id: str,
) -> float:
    """PolicyEngine.evaluate after FirewallCore.submit has folded prefix events."""
    fw = make_firewall(registry, engine, with_monitor=False)
    replay_prefix(fw, item.prefix, session_id)
    state = fw._get_state(session_id)
    seq = fw._action_seqs.get(session_id, 0) + 1
    action = canonical_action_from_request(bind_session(item.target, session_id), seq=seq)
    t0 = time.perf_counter_ns()
    engine.evaluate(action, state, registry)
    return _elapsed_ms(t0)


def measure_policy_state_monitor(
    engine: PolicyEngine,
    registry: Registry,
    item: WorkItem,
    session_id: str,
) -> float:
    """
    Real decision-stage functions used by FirewallCore.submit:
    PolicyEngine.evaluate, then monitor advice if that branch consults a monitor,
    then combinator.decide or CascadeAdapter.decide.
    Excludes session lock, audit, review tickets, and executor.
    """
    fw = make_firewall(registry, engine, with_monitor=False)
    replay_prefix(fw, item.prefix, session_id)
    state = fw._get_state(session_id)
    seq = fw._action_seqs.get(session_id, 0) + 1
    target = bind_session(item.target, session_id)
    action = canonical_action_from_request(target, seq=seq)
    tool_info = registry.get_tool(action.tool)
    cfg = DecisionConfig(monitor_authority="escalate_only")
    monitor = SafeMonitorWrapper(DeterministicMockMonitor())
    cascade = CascadeAdapter(monitor=monitor, suspicious_map=cfg.suspicious_map)
    adapter_mon = cascade.monitor
    cand_id = getattr(adapter_mon, "monitor_id", None) if adapter_mon else None
    cascade_monitor_id = cand_id if isinstance(cand_id, str) else "cascade_monitor"

    t0 = time.perf_counter_ns()
    policy_result = engine.evaluate(action, state, registry)
    if tool_info is None:
        decide(
            valid=False,
            policy_verdict=PolicyVerdict.UNDETERMINED,
            validation_error=f"UNKNOWN_TOOL:{action.tool}",
            config=cfg,
        )
    elif policy_result.verdict == PolicyVerdict.PERMIT:
        # Mirrors FirewallCore.submit: mandatory-review consults the monitor
        # without combinator.decide; escalate_only consults then calls decide().
        if tool_info.tool_class in cfg.mandatory_review_classes or (
            cfg.monitor_authority == "escalate_only"
        ):
            view = build_monitor_view(
                monitor_type=monitor.monitor_id,
                action=action,
                state=state,
                registry=registry,
            )
            assessment = monitor.assess(view)
            if tool_info.tool_class not in cfg.mandatory_review_classes:
                decide(
                    valid=True,
                    policy_verdict=policy_result.verdict,
                    monitor_verdict=assessment.verdict,
                    tool_class=tool_info.tool_class,
                    config=cfg,
                    matched_rules=policy_result.matched_rules,
                    missing_fields=policy_result.missing_fields,
                )
        else:
            decide(
                valid=True,
                policy_verdict=policy_result.verdict,
                tool_class=tool_info.tool_class,
                config=cfg,
                matched_rules=policy_result.matched_rules,
                missing_fields=policy_result.missing_fields,
            )
    elif policy_result.verdict == PolicyVerdict.UNDETERMINED:
        view = build_monitor_view(
            monitor_type=cascade_monitor_id,
            action=action,
            state=state,
            registry=registry,
        )
        cascade.decide(
            policy_verdict=PolicyVerdict.UNDETERMINED,
            action=action,
            view=view,
            tool=action.tool,
            arguments=action.arguments,
        )
    else:
        decide(
            valid=True,
            policy_verdict=policy_result.verdict,
            tool_class=tool_info.tool_class,
            config=cfg,
            matched_rules=policy_result.matched_rules,
            missing_fields=policy_result.missing_fields,
        )
    return _elapsed_ms(t0)


def measure_full(
    engine: PolicyEngine,
    registry: Registry,
    item: WorkItem,
    session_id: str,
) -> float:
    """Measure submit through decision audit append, stopping before executor work."""
    audit_store = _DecisionAuditStore()
    fw = make_firewall(registry, engine, with_monitor=True, audit_store=audit_store)
    replay_prefix(fw, item.prefix, session_id)
    target = bind_session(item.target, session_id)
    # Drop prefix/warm-up ROUTE_TRACE timestamps so a missed append cannot reuse them.
    audit_store.decision_audit_completed_ns = None
    t0 = time.perf_counter_ns()
    fw.submit(target)
    completed = audit_store.decision_audit_completed_ns
    if completed is None or completed < t0:
        raise RuntimeError(
            "FirewallCore.submit did not append a new decision ROUTE_TRACE audit record"
        )
    return _elapsed_ms(t0, completed)


def measure_audit(session_id: str, iteration: int) -> float:
    """AuditStore.append only; this is invoked from FirewallCore._record_decision_audit."""
    store = AuditStore()
    payload = {
        "action_id": f"bench_{iteration}",
        "decision": Decision.ALLOW.value,
        "reason_codes": ["BENCHMARK_AUDIT"],
    }
    t0 = time.perf_counter_ns()
    store.append(session_id=session_id, record_type="DECISION", payload=payload)
    return _elapsed_ms(t0)


def select_item(
    items: Sequence[WorkItem],
    path: str,
    iteration: int,
    *,
    synthetic: bool,
) -> WorkItem:
    """
    Choose the WorkItem for this iteration.

    Dataset items already target the trace critical_step_index (or last action).
    For --path full, policy, and policy-state-monitor, that critical action is used
    as-is; validate_schema is not preferred when the critical tool differs.
    Synthetic-request mode keeps the previous permit vs stateful split.
    """
    if not synthetic:
        if path == PATH_POLICY_STATE:
            stateful = [i for i in items if i.prefix]
            pool = stateful or list(items)
        else:
            pool = list(items)
        return pool[iteration % len(pool)]
    if path in (PATH_POLICY, PATH_POLICY_STATE_MONITOR, PATH_FULL, PATH_AUDIT):
        permit = [i for i in items if i.target.tool == "validate_schema"]
        pool = permit or list(items)
    else:
        stateful = [i for i in items if i.prefix]
        pool = stateful or list(items)
    return pool[iteration % len(pool)]


def run_benchmark(
    path: str,
    warmup: int,
    runs: int,
    items: Sequence[WorkItem],
    *,
    synthetic: bool = True,
) -> list[float]:
    if warmup < 0:
        raise ValueError("--warmup must be >= 0")
    if runs < 1:
        raise ValueError("--runs must be >= 1")
    if path not in BENCHMARK_PATHS:
        raise ValueError(f"Unknown path {path!r}; expected one of {BENCHMARK_PATHS}")

    registry = create_default_eval_registry()
    engine = create_default_stateful_policy()
    samples: list[float] = []

    def timed_once(iteration: int) -> float:
        session_id = f"bench_{path}_{iteration}"
        item = select_item(items, path, iteration, synthetic=synthetic)
        if path == PATH_POLICY:
            return measure_policy(engine, registry, item, session_id)
        if path == PATH_POLICY_STATE:
            return measure_policy_state(engine, registry, item, session_id)
        if path == PATH_POLICY_STATE_MONITOR:
            return measure_policy_state_monitor(engine, registry, item, session_id)
        if path == PATH_FULL:
            return measure_full(engine, registry, item, session_id)
        return measure_audit(session_id, iteration)

    for i in range(warmup):
        timed_once(i)
    for i in range(runs):
        samples.append(timed_once(warmup + i))
    return samples


PATH_DEFINITIONS: dict[str, dict[str, str]] = {
    PATH_POLICY: {
        "timed": "PolicyEngine.evaluate",
        "start": "immediately before PolicyEngine.evaluate",
        "stop": "immediately after PolicyEngine.evaluate returns",
        "definition": (
            "Latency of PolicyEngine.evaluate(action, initial_state, registry). "
            "PolicyEngine.evaluate is not separately callable without a SessionState "
            "argument; this path uses initial_state()."
        ),
    },
    PATH_POLICY_STATE: {
        "timed": "PolicyEngine.evaluate after FirewallCore.submit prefix fold",
        "start": "immediately before PolicyEngine.evaluate on folded SessionState",
        "stop": "immediately after PolicyEngine.evaluate returns",
        "definition": (
            "Untimed prefix actions are submitted through FirewallCore.submit so "
            "session state is the real fold. Timing covers only PolicyEngine.evaluate "
            "on that state."
        ),
    },
    PATH_POLICY_STATE_MONITOR: {
        "timed": (
            "PolicyEngine.evaluate + SafeMonitorWrapper.assess/"
            "CascadeAdapter.decide + combinator.decide"
        ),
        "start": "immediately before PolicyEngine.evaluate",
        "stop": "immediately after combinator.decide or CascadeAdapter.decide returns",
        "definition": (
            "Composes the decision-stage calls used by FirewallCore.submit "
            "(policy, optional monitor advice, final combinator/cascade decision). "
            "Does not call AuditStore, ReviewService, or ControlledExecutor."
        ),
    },
    PATH_FULL: {
        "timed": "FirewallCore.submit through AuditStore.append(ROUTE_TRACE)",
        "start": "immediately before FirewallCore.submit(target)",
        "stop": "immediately after the decision ROUTE_TRACE append returns",
        "definition": (
            "Wall-clock latency from FirewallCore.submit entry through the decision "
            "and hash-chained DECISION/ROUTE_TRACE audit appends. Stops before "
            "post-decision ReviewService or ControlledExecutor work. Includes "
            "policy, state lookup, monitor advice when that branch consults a "
            "monitor, combinator/cascade decision, and decision audit. "
            "Prefix actions are submitted untimed. RouteTrace.latency_ms inside "
            "submit stops before decision audit."
        ),
    },
    PATH_AUDIT: {
        "timed": "AuditStore.append",
        "start": "immediately before AuditStore.append",
        "stop": "immediately after AuditStore.append returns",
        "definition": (
            "Isolated hash-chained audit write. FirewallCore._record_decision_audit "
            "calls this after the in-core decision timer stops."
        ),
    },
}


def format_summary(
    path: str,
    warmup: int,
    source: str,
    summary: LatencySummary,
) -> str:
    meta = PATH_DEFINITIONS[path]
    return "\n".join(
        [
            "AASF action-decision latency",
            f"  path:     {path}",
            f"  timed:    {meta['timed']}",
            f"  source:   {source}",
            f"  warmup:   {warmup}  measured: {summary.n}",
            (
                f"  mean={summary.mean_ms:.4f}ms  median={summary.median_ms:.4f}ms  "
                f"p50={summary.p50_ms:.4f}ms  p95={summary.p95_ms:.4f}ms  "
                f"p99={summary.p99_ms:.4f}ms"
            ),
            (
                f"  min={summary.min_ms:.4f}ms  max={summary.max_ms:.4f}ms  "
                f"stdev={summary.stdev_ms:.4f}ms  n={summary.n}"
            ),
        ]
    )


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark latency of one AASF firewall action decision. "
            "Default mode uses synthetic ActionRequests, not DEV/H1 evaluation. "
            "--dataset supplies actions to this benchmark only and does not run "
            "experiments.evaluate. experiments.evaluate times the whole "
            "FirewallCore.submit call, including executor work. "
            "--path full starts before FirewallCore.submit(target) and stops after "
            "the decision ROUTE_TRACE AuditStore.append, before ReviewService/"
            "ControlledExecutor post-decision work."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help=(
            "DEV-compatible trace file or directory used only to supply actions "
            "to this benchmark. Does not run experiments.evaluate. Omitted uses "
            "synthetic ActionRequests, not DEV/H1 evaluation"
        ),
    )
    parser.add_argument("--warmup", type=int, default=100, help="Untimed warm-up iterations")
    parser.add_argument("--runs", type=int, default=1000, help="Measured iterations")
    parser.add_argument(
        "--path",
        choices=list(BENCHMARK_PATHS),
        default=PATH_FULL,
        help=(
            "Which real functions to time. 'full' starts before "
            "FirewallCore.submit(target) and stops after the decision "
            "ROUTE_TRACE AuditStore.append, before ReviewService/"
            "ControlledExecutor post-decision work"
        ),
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional JSON artifact path for raw samples and summary stats",
    )
    return parser.parse_args(args)


def main(args: Optional[list[str]] = None) -> int:
    opts = parse_args(args)
    try:
        items, source = load_work_items(opts.dataset)
        synthetic = source == "synthetic_action_requests"
        samples = run_benchmark(
            opts.path, opts.warmup, opts.runs, items, synthetic=synthetic
        )
        summary = summarize_latencies_ms(samples)
    except (FileNotFoundError, PermissionError, ValueError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(format_summary(opts.path, opts.warmup, source, summary))

    if opts.output:
        out_path = Path(opts.output)
        payload: dict[str, Any] = {
            "path": opts.path,
            "source": source,
            "warmup": opts.warmup,
            "runs": opts.runs,
            "unit": "ms",
            "timed_function": PATH_DEFINITIONS[opts.path]["timed"],
            "latency_definition": PATH_DEFINITIONS[opts.path]["definition"],
            "mean_ms": summary.mean_ms,
            "median_ms": summary.median_ms,
            "p50_ms": summary.p50_ms,
            "p95_ms": summary.p95_ms,
            "p99_ms": summary.p99_ms,
            "min_ms": summary.min_ms,
            "max_ms": summary.max_ms,
            "stdev_ms": summary.stdev_ms,
            "n": summary.n,
            "samples_ms": samples,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"  wrote:    {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

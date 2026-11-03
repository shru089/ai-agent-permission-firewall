"""
AASF Latency Microbenchmark Test Suite (Canonical Implementation).

Profiles and records component-level latencies and end-to-end processing times
using the authoritative AASF runtime components:
- Token minting and validation (TokenStore)
- Audit log hash chaining (AuditStore)
- Deterministic policy evaluation (PolicyEngine)
- Full Track A FirewallCore interception and execution pipeline
"""

import json
import os
import statistics
import sys
import time
from pathlib import Path

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
src_path = os.path.join(repo_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from firewall.audit.store import AuditStore
from firewall.contracts.enums import (
    Classification,
    Decision,
    EventType,
    PolicyVerdict,
    ToolClass,
    Zone,
)
from firewall.contracts.hashing import compute_action_hash
from firewall.contracts.models import ActionRequest, CanonicalAction
from firewall.core import FirewallCore
from firewall.executor.tokens import TokenStore
from firewall.policy.evaluator import create_default_stateful_policy
from firewall.state.models import SessionState
from firewall.state.registry import DestinationInfo, Registry, ResourceInfo, ToolInfo


def create_benchmark_registry() -> Registry:
    return Registry(
        resources={
            "customer_records": ResourceInfo(classification=Classification.CONFIDENTIAL, rows=5000),
            "public_records": ResourceInfo(classification=Classification.PUBLIC, rows=800),
        },
        destinations={
            "external_storage": DestinationInfo(zone=Zone.EXTERNAL),
            "internal_archive": DestinationInfo(zone=Zone.INTERNAL),
        },
        tools={
            "validate_schema": ToolInfo(tool_class=ToolClass.READ_LOW),
            "select_resource": ToolInfo(tool_class=ToolClass.READ_SENSITIVE),
            "configure_destination": ToolInfo(tool_class=ToolClass.WRITE_INTERNAL),
            "execute_export": ToolInfo(tool_class=ToolClass.EGRESS_EXTERNAL),
        },
    )


def benchmark_component_micros(iterations=1000) -> dict:
    """Measures latency for isolated deterministic components."""
    results = {}

    # 1. Token minting & consumption
    store = TokenStore(secret_key=b"benchmarking_secret_key_32_bytes!", ttl_seconds=60)
    mint_times = []
    consume_times = []
    dummy_hash = b"\xaa" * 32

    for i in range(iterations):
        sess_id = f"sess_{i}"
        act_id = f"act_{i}"
        t0 = time.perf_counter()
        tok = store.issue_token(sess_id, act_id, "validate_schema", dummy_hash)
        t1 = time.perf_counter()
        mint_times.append((t1 - t0) * 1000)

        t2 = time.perf_counter()
        store.consume(tok.token_id, sess_id, act_id, "validate_schema", dummy_hash)
        t3 = time.perf_counter()
        consume_times.append((t3 - t2) * 1000)

    results["token_mint_mean_ms"] = round(statistics.mean(mint_times), 4)
    results["token_mint_median_ms"] = round(statistics.median(mint_times), 4)
    results["token_consume_mean_ms"] = round(statistics.mean(consume_times), 4)
    results["token_consume_median_ms"] = round(statistics.median(consume_times), 4)

    # 2. Audit Store event recording & cryptographic hash chaining
    audit = AuditStore()
    audit_times = []
    for i in range(iterations):
        t0 = time.perf_counter()
        audit.append(
            session_id=f"sess_{i % 10}",
            event_type=EventType.DECISION_MADE,
            payload={"action_id": f"act_{i}", "verdict": "ALLOW"},
        )
        t1 = time.perf_counter()
        audit_times.append((t1 - t0) * 1000)

    results["audit_append_mean_ms"] = round(statistics.mean(audit_times), 4)
    results["audit_append_median_ms"] = round(statistics.median(audit_times), 4)

    # 3. Policy evaluation
    policy = create_default_stateful_policy()
    registry = create_benchmark_registry()
    state = SessionState(session_id="bench_sess")
    action = CanonicalAction(
        action_id="act_bench",
        session_id="bench_sess",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash=compute_action_hash("bench_sess", 1, "validate_schema", {}),
    )
    policy_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        policy.evaluate(action, state, registry)
        t1 = time.perf_counter()
        policy_times.append((t1 - t0) * 1000)

    results["policy_eval_mean_ms"] = round(statistics.mean(policy_times), 4)
    results["policy_eval_median_ms"] = round(statistics.median(policy_times), 4)

    return results


def benchmark_pipeline_configurations(iterations=500) -> dict:
    """Profiles full Track A FirewallCore pipeline latency."""
    registry = create_benchmark_registry()
    fw = FirewallCore(registry=registry)

    # C4: Full Track A Permitted Action (Interception -> State -> Policy -> Token -> Controlled Exec -> Audit)
    c4_times = []
    for i in range(iterations):
        req = ActionRequest(
            session_id=f"sess_c4_{i}",
            tool="validate_schema",
            arguments={},
        )
        t0 = time.perf_counter()
        resp = fw.submit(req)
        t1 = time.perf_counter()
        assert resp.status == "EXECUTED"
        c4_times.append((t1 - t0) * 1000)

    c4_times.sort()
    summary = {
        "C4_full_track_a_permit": {
            "mean_ms": round(statistics.mean(c4_times), 3),
            "median_ms": round(statistics.median(c4_times), 3),
            "p90_ms": round(c4_times[int(iterations * 0.90)], 3),
            "p95_ms": round(c4_times[int(iterations * 0.95)], 3),
            "p99_ms": round(c4_times[int(iterations * 0.99)], 3),
            "min_ms": round(min(c4_times), 3),
            "max_ms": round(max(c4_times), 3),
        }
    }
    return summary


def run_all_benchmarks():
    print("=" * 60)
    print("Running AASF Canonical Latency Microbenchmarks...")
    print("=" * 60)

    micros = benchmark_component_micros(iterations=500)
    print("\nComponent Micro-Latencies (ms):")
    print(json.dumps(micros, indent=2))

    pipeline = benchmark_pipeline_configurations(iterations=500)
    print("\nPipeline Latencies (ms):")
    print(json.dumps(pipeline, indent=2))

    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iterations": 500,
        "component_micros": micros,
        "pipeline_configs": pipeline,
    }

    out_file = Path(repo_root) / "AASF_FINAL_AUDIT" / "benchmark_results.json"
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nSaved benchmark results to {out_file}")
    return output


if __name__ == "__main__":
    run_all_benchmarks()

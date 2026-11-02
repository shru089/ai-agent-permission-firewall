"""Run a small real decision-path demonstration of the AASF firewall."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# The project uses a src/ layout and the requested command runs from the repo root.
REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from experiments.evaluate import (  # noqa: E402
    TraceAction,
    create_default_eval_registry,
    make_clean_action_request,
)
from firewall.audit.store import AuditStore  # noqa: E402
from firewall.contracts.enums import Decision  # noqa: E402
from firewall.core import FirewallCore  # noqa: E402


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def run_example(
    firewall: FirewallCore,
    audit_store: AuditStore,
    *,
    label: str,
    session_id: str,
    tool: str,
    arguments: dict[str, Any],
    expected_decision: Decision,
) -> bool:
    action = TraceAction(step_index=1, tool=tool, arguments=arguments)
    request = make_clean_action_request(session_id, action)

    print(f"\n=== {label} ===")
    print("Request:")
    print(f"  session_id: {request.session_id}")
    print(f"  tool:       {request.tool}")
    print(f"  arguments:  {request.arguments}")

    response = firewall.submit(request)
    print("Firewall decision:")
    print(f"  decision:       {_value(response.decision)}")
    print(f"  status:         {response.status}")
    print(f"  policy verdict: {_value(response.policy_verdict)}")
    print(f"  monitor verdict: {_value(response.monitor_verdict)}")
    print(f"  reason codes:   {response.reason_codes}")
    if response.route_trace is not None:
        print(f"  route path:     {response.route_trace.path}")
        print(f"  monitor called: {response.route_trace.monitor_invoked}")

    records = [
        record
        for record in audit_store.get_records(session_id)
        if record.type in {"DECISION", "ROUTE_TRACE"}
    ]
    decision_record = next((r for r in records if r.type == "DECISION"), None)
    route_record = next((r for r in records if r.type == "ROUTE_TRACE"), None)
    print("Audit records:")
    if decision_record is not None:
        payload = decision_record.payload
        print(
            "  DECISION: "
            f"decision={_value(payload.get('decision'))}, "
            f"policy_verdict={_value(payload.get('policy_verdict'))}, "
            f"monitor_verdict={_value(payload.get('monitor_verdict'))}, "
            f"reason_codes={payload.get('reason_codes')}"
        )
    if route_record is not None:
        payload = route_record.payload
        print(
            "  ROUTE_TRACE: "
            f"path={payload.get('path')}, "
            f"final_decision={_value(payload.get('final_decision'))}, "
            f"monitor_invoked={payload.get('monitor_invoked')}, "
            f"reason_codes={payload.get('reason_codes')}"
        )

    chain_valid = audit_store.verify_chain(session_id)
    print(f"  audit chain valid: {chain_valid}")
    records_valid = (
        decision_record is not None
        and route_record is not None
        and _value(decision_record.payload.get("decision")) == expected_decision.value
        and _value(route_record.payload.get("final_decision")) == expected_decision.value
        and chain_valid
    )
    return response.decision == expected_decision and records_valid


def main() -> int:
    registry = create_default_eval_registry()
    audit_store = AuditStore()
    firewall = FirewallCore(registry=registry, audit_store=audit_store)

    allow_ok = run_example(
        firewall,
        audit_store,
        label="Permitted action",
        session_id="demo-allow",
        tool="validate_schema",
        arguments={},
        expected_decision=Decision.ALLOW,
    )
    deny_ok = run_example(
        firewall,
        audit_store,
        label="Prohibited action",
        session_id="demo-deny",
        tool="relabel_resource",
        arguments={"resource_ref": "customer_records", "classification": "PUBLIC"},
        expected_decision=Decision.DENY,
    )

    if not (allow_ok and deny_ok):
        print("\nDemo failed: observed decisions or required audit records did not match.")
        return 1

    print("\nDemo completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

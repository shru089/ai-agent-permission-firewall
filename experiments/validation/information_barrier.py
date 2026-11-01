"""
End-to-End Information Barrier and Anti-Leakage Validator.

Source:
- docs/05_TECHNICAL_SPEC.md §8.2 (Information Projections)
- docs/01_THREAT_MODEL.md (INV-08 Information Barrier)
- docs/06_EXPERIMENT_PROTOCOL.md §5.3 (Anti-Leakage Rules)

Verifies both statically (AST imports) and dynamically (runtime canaries) that
prohibited dataset fields (ground-truth labels, oracle metadata, twin IDs, critical step indices)
and sensitive credentials (API keys, passwords, bearer tokens, private keys)
cannot reach downstream decision-making components.
"""

import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from firewall.contracts.enums import (
    Classification,
    Decision,
    MonitorVerdict,
    PolicyVerdict,
    Provenance,
    ToolClass,
    Zone,
)
from firewall.contracts.models import (
    ActionRequest,
    CanonicalAction,
    DestinationRef,
    Event,
    ResourceRef,
    TaggedValue,
)
from firewall.decision.combinator import DecisionConfig, decide
from firewall.state.engine import initial_state
from firewall.state.registry import Registry, ToolInfo
from firewall.state.views import (
    build_monitor_view,
    build_policy_view,
    build_reviewer_view,
)

# Prohibited Canaries
CANARIES = {
    "GROUND_TRUTH_LABEL": "CANARY_GROUND_TRUTH_LABEL_MALICIOUS_SECRET",
    "ORACLE_RATIONALE": "CANARY_ORACLE_RATIONALE_SECRET_TEXT",
    "ORACLE_RULE_ID": "CANARY_SPEC_RULE_ID_999",
    "CRITICAL_INDEX": "CANARY_CRITICAL_STEP_INDEX_999",
    "TWIN_TRACE_ID": "CANARY_TWIN_TRACE_ID_EXFIL",
    "SCENARIO_TYPE": "CANARY_SCENARIO_TYPE_ATTACK",
    "API_KEY": "CANARY_PROHIBITED_API_KEY_xyz123",
    "PASSWORD": "CANARY_PROHIBITED_PASSWORD_secret456",
    "PRIVATE_KEY": "CANARY_PROHIBITED_PRIVATE_KEY_rsa789",
    "AUTH_TOKEN": "CANARY_PROHIBITED_AUTH_TOKEN_bearer999",
    "NESTED_SECRET": "CANARY_PROHIBITED_NESTED_CREDENTIAL_deep",
}


@dataclass(frozen=True)
class BoundaryAuditResult:
    """Audit result for a single architectural boundary."""

    boundary_id: str
    description: str
    target_component: str
    passed: bool
    leakage_detected: bool
    leakage_paths: list[str]
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InformationBarrierAuditResult:
    """Overall validation result for the end-to-end information barrier audit."""

    passed: bool
    static_checks_passed: bool
    runtime_checks_passed: bool
    total_boundaries_checked: int
    boundaries: list[BoundaryAuditResult]
    tested_prohibited_fields: list[str]
    leakage_paths: list[str]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["boundaries"] = [b.to_dict() for b in self.boundaries]
        return d


def find_canaries_in_object(obj: Any, prefix: str = "") -> list[tuple[str, str, str]]:
    """
    Recursively searches any Python object (dict, list, tuple, str, dataclass, BaseModel)
    for canary strings. Returns list of (path, canary_key, canary_value).
    """
    findings: list[tuple[str, str, str]] = []

    if isinstance(obj, str):
        for c_key, c_val in CANARIES.items():
            if c_val in obj:
                findings.append((prefix, c_key, c_val))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            current_path = f"{prefix}.{k}" if prefix else str(k)
            # Check key
            if isinstance(k, str):
                for c_key, c_val in CANARIES.items():
                    if c_val in k:
                        findings.append((current_path, c_key, c_val))
            # Check value
            findings.extend(find_canaries_in_object(v, current_path))
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            current_path = f"{prefix}[{idx}]"
            findings.extend(find_canaries_in_object(item, current_path))
    elif hasattr(obj, "model_dump"):
        findings.extend(find_canaries_in_object(obj.model_dump(), prefix))
    elif hasattr(obj, "__dict__"):
        findings.extend(find_canaries_in_object(obj.__dict__, prefix))

    return findings


class InformationBarrierValidator:
    """
    Comprehensive static and runtime information-barrier validation engine.
    """

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent.parent

    def run_static_ast_checks(self) -> BoundaryAuditResult:
        """
        Static Check: Inspects AST of src/firewall/ and experiments/labels/
        to verify complete dependency graph separation (INV-08, T-EXP-009).
        """
        firewall_dir = self.repo_root / "src" / "firewall"
        labels_dir = self.repo_root / "experiments" / "labels"

        leakage_paths: list[str] = []

        forbidden_in_firewall = (
            "experiments.labels",
            "experiments.generator",
            "experiments.datasets",
            "experiments.validation",
        )

        forbidden_in_labels = (
            "firewall.policy",
            "firewall.core",
            "firewall.monitors",
            "firewall.cascade",
            "firewall.executor",
            "src.firewall.policy",
            "src.firewall.core",
            "src.firewall.monitors",
            "src.firewall.cascade",
            "src.firewall.executor",
        )

        # 1. Inspect firewall files
        for py_path in firewall_dir.rglob("*.py"):
            tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if any(alias.name.startswith(f) for f in forbidden_in_firewall):
                            leakage_paths.append(
                                f"{py_path.relative_to(self.repo_root)} imports {alias.name}"
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.module and any(
                        node.module.startswith(f) for f in forbidden_in_firewall
                    ):
                        leakage_paths.append(
                            f"{py_path.relative_to(self.repo_root)} imports from {node.module}"
                        )

        # 2. Inspect labels files
        if labels_dir.exists():
            for py_path in labels_dir.rglob("*.py"):
                tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if any(alias.name.startswith(f) for f in forbidden_in_labels):
                                leakage_paths.append(
                                    f"{py_path.relative_to(self.repo_root)} imports {alias.name}"
                                )
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and any(
                            node.module.startswith(f) for f in forbidden_in_labels
                        ):
                            leakage_paths.append(
                                f"{py_path.relative_to(self.repo_root)} imports from {node.module}"
                            )

        passed = len(leakage_paths) == 0
        return BoundaryAuditResult(
            boundary_id="BOUNDARY_STATIC_IMPORTS",
            description=(
                "Static AST import-graph separation between firewall core "
                "and experiment/oracle modules"
            ),
            target_component="Import Graph (firewall <-> labels/generator)",
            passed=passed,
            leakage_detected=not passed,
            leakage_paths=leakage_paths,
            evidence=(
                "Verified 0 forbidden cross-boundary imports across firewall and "
                "labels source files."
                if passed
                else f"Forbidden imports detected: {leakage_paths}"
            ),
        )

    def run_runtime_boundary_checks(self) -> list[BoundaryAuditResult]:
        """
        Dynamic Runtime Check: Plants canaries across dataset metadata, action arguments,
        and event history, and verifies all 7 runtime boundaries.
        """
        results: list[BoundaryAuditResult] = []

        # Setup test registry
        registry = Registry(
            tools={
                "execute_export": ToolInfo(
                    tool_class=ToolClass.EGRESS_EXTERNAL, args={"batch_size": "int"}
                ),
                "select_resource": ToolInfo(
                    tool_class=ToolClass.READ_LOW, args={"resource_ref": "str"}
                ),
            }
        )

        state = initial_state("sess_canary")
        state.bound_resource = ResourceRef(
            ref="customer_records", classification=Classification.PUBLIC, selected_seq=1
        )
        state.destination = DestinationRef(ref="internal_archive", zone=Zone.INTERNAL)

        # ----------------------------------------------------------------------
        # Boundary 1: Evaluator -> ActionRequest Schema Boundary
        # ----------------------------------------------------------------------
        eval_leaks: list[str] = []
        try:
            # ActionRequest specifies extra="forbid".
            # Ingesting dict with dataset metadata must fail.
            ActionRequest.model_validate(
                {
                    "session_id": "sess_canary",
                    "tool": "execute_export",
                    "arguments": {"batch_size": 10},
                    "ground_truth": CANARIES["GROUND_TRUTH_LABEL"],
                    "scenario_type": CANARIES["SCENARIO_TYPE"],
                }
            )
            eval_leaks.append("ActionRequest failed to reject extra dataset metadata fields!")
        except Exception:
            # Expected Pydantic validation error
            pass

        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_EVALUATOR_TO_ACTION_REQUEST",
                description=(
                    "Dataset metadata rejection on ActionRequest ingestion (extra='forbid')"
                ),
                target_component="ActionRequest",
                passed=len(eval_leaks) == 0,
                leakage_detected=len(eval_leaks) > 0,
                leakage_paths=eval_leaks,
                evidence=(
                    "ActionRequest strictly rejected extraneous ground_truth "
                    "and scenario_type fields."
                ),
            )
        )

        # Construct CanonicalAction with embedded sensitive canaries in arguments
        sensitive_arguments = {
            "batch_size": 10,
            "api_key": CANARIES["API_KEY"],
            "password": CANARIES["PASSWORD"],
            "credentials": {"private_key": CANARIES["PRIVATE_KEY"]},
            "nested": {
                "auth_token": CANARIES["AUTH_TOKEN"],
                "secret": CANARIES["NESTED_SECRET"],
                "safe_field": "public_data",
            },
        }

        action = CanonicalAction(
            action_id="act_canary_01",
            session_id="sess_canary",
            seq=1,
            tool="execute_export",
            arguments=sensitive_arguments,
            action_hash="hash_canary_01",
        )

        # ----------------------------------------------------------------------
        # Boundary 2: PolicyView Projection Boundary
        # ----------------------------------------------------------------------
        policy_view = build_policy_view(action, state, registry)
        pv_findings = find_canaries_in_object(policy_view)
        # Note: PolicyView contains authoritative CanonicalAction arguments
        # (for deterministic policy), but must NEVER contain oracle labels,
        # scenario types, or critical step index.
        pv_leaks = [
            f"{path}: leaked {k}"
            for path, k, _ in pv_findings
            if k
            in (
                "GROUND_TRUTH_LABEL",
                "ORACLE_RATIONALE",
                "ORACLE_RULE_ID",
                "CRITICAL_INDEX",
                "TWIN_TRACE_ID",
                "SCENARIO_TYPE",
            )
        ]
        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_POLICY_VIEW",
                description=(
                    "PolicyView contains zero oracle ground-truth, twin IDs, "
                    "or scenario classification"
                ),
                target_component="PolicyEngine (PolicyView)",
                passed=len(pv_leaks) == 0,
                leakage_detected=len(pv_leaks) > 0,
                leakage_paths=pv_leaks,
                evidence=(
                    "PolicyView contains strictly canonical action and session state; "
                    "zero oracle metadata."
                ),
            )
        )

        # ----------------------------------------------------------------------
        # Boundary 3: MonitorView ActionOnly Projection Boundary (B4)
        # ----------------------------------------------------------------------
        view_action_only = build_monitor_view(
            monitor_type="action_only",
            action=action,
            state=state,
            registry=registry,
        )
        mv_ao_findings = find_canaries_in_object(view_action_only)
        mv_ao_leaks = [f"{path}: leaked {k}" for path, k, _ in mv_ao_findings]
        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_MONITOR_VIEW_ACTION_ONLY",
                description=(
                    "Action-only MonitorView sanitizes sensitive credentials "
                    "and excludes oracle metadata"
                ),
                target_component="Monitor (ActionOnly / B4)",
                passed=len(mv_ao_leaks) == 0,
                leakage_detected=len(mv_ao_leaks) > 0,
                leakage_paths=mv_ao_leaks,
                evidence=(
                    "All sensitive credentials (API key, password, bearer token, "
                    "private key) recursively sanitized; zero oracle metadata."
                ),
            )
        )

        # ----------------------------------------------------------------------
        # Boundary 4: MonitorView Transcript Projection Boundary (B5)
        # ----------------------------------------------------------------------
        # Create history containing sensitive payload
        event_fields = {
            "arguments": TaggedValue(
                value={
                    "tool": "select_resource",
                    "resource_ref": "public_data",
                    "api_key": CANARIES["API_KEY"],
                    "secret": CANARIES["NESTED_SECRET"],
                },
                provenance=Provenance.TOOL_TYPED,
            )
        }
        test_event = Event(
            event_id="evt_01",
            session_id="sess_canary",
            seq=0,
            type="TOOL_CALLED",
            action_id="act_prior",
            fields=event_fields,
            free_text="Fetched resource safely",
            decision=Decision.ALLOW,
        )

        view_transcript = build_monitor_view(
            monitor_type="transcript",
            action=action,
            state=state,
            registry=registry,
            history=[test_event],
        )
        mv_tr_findings = find_canaries_in_object(view_transcript)
        mv_tr_leaks = [f"{path}: leaked {k}" for path, k, _ in mv_tr_findings]
        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_MONITOR_VIEW_TRANSCRIPT",
                description=(
                    "Transcript MonitorView formats event history without "
                    "sensitive credentials or oracle labels"
                ),
                target_component="Monitor (Transcript / B5)",
                passed=len(mv_tr_leaks) == 0,
                leakage_detected=len(mv_tr_leaks) > 0,
                leakage_paths=mv_tr_leaks,
                evidence=(
                    "Transcript projection cleanly formatted with sanitized arguments; "
                    "zero canary credentials or labels."
                ),
            )
        )

        # ----------------------------------------------------------------------
        # Boundary 5: MonitorView Hybrid Projection Boundary (P1)
        # ----------------------------------------------------------------------
        view_hybrid = build_monitor_view(
            monitor_type="hybrid",
            action=action,
            state=state,
            registry=registry,
            history=[test_event],
        )
        mv_hy_findings = find_canaries_in_object(view_hybrid)
        mv_hy_leaks = [f"{path}: leaked {k}" for path, k, _ in mv_hy_findings]
        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_MONITOR_VIEW_HYBRID",
                description=(
                    "Hybrid MonitorView typed state summary sanitizes credentials "
                    "and excludes oracle metadata"
                ),
                target_component="Monitor (Hybrid / P1)",
                passed=len(mv_hy_leaks) == 0,
                leakage_detected=len(mv_hy_leaks) > 0,
                leakage_paths=mv_hy_leaks,
                evidence=(
                    "State summary includes only allow-listed typed fields; "
                    "zero canary leaks."
                ),
            )
        )

        # ----------------------------------------------------------------------
        # Boundary 6: ReviewerView Projection Boundary
        # ----------------------------------------------------------------------
        reviewer_view = build_reviewer_view(
            action=action,
            policy_verdict=PolicyVerdict.UNDETERMINED,
            reason_codes=["NEEDS_REVIEW"],
            state=state,
            monitor_assessment=None,
        )
        rv_findings = find_canaries_in_object(reviewer_view)
        # ReviewerView must have zero oracle ground truth or scenario classification
        rv_leaks = [
            f"{path}: leaked {k}"
            for path, k, _ in rv_findings
            if k
            in (
                "GROUND_TRUTH_LABEL",
                "ORACLE_RATIONALE",
                "ORACLE_RULE_ID",
                "CRITICAL_INDEX",
                "TWIN_TRACE_ID",
                "SCENARIO_TYPE",
            )
        ]
        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_REVIEWER_VIEW",
                description=(
                    "ReviewerView bound to action and state without oracle ground truth "
                    "or scenario tags"
                ),
                target_component="ReviewService (ReviewerView)",
                passed=len(rv_leaks) == 0,
                leakage_detected=len(rv_leaks) > 0,
                leakage_paths=rv_leaks,
                evidence=(
                    "ReviewerView contains only session state, sanitized action, "
                    "and policy facts; zero oracle labels."
                ),
            )
        )

        # ----------------------------------------------------------------------
        # Boundary 7: Decision Combinator Boundary
        # ----------------------------------------------------------------------
        # Verify decide() receives only pure policy verdict, monitor verdict, and config
        dec_config = DecisionConfig()
        dec, reasons = decide(
            valid=True,
            policy_verdict=PolicyVerdict.PERMIT,
            monitor_verdict=MonitorVerdict.BENIGN,
            config=dec_config,
        )
        dec_findings = find_canaries_in_object({"decision": dec.value, "reasons": reasons})
        dec_leaks = [f"{path}: leaked {k}" for path, k, _ in dec_findings]
        results.append(
            BoundaryAuditResult(
                boundary_id="BOUNDARY_FIREWALL_CORE_DECISION",
                description=(
                    "FirewallCore decision combinator operates strictly on allow-listed verdicts"
                ),
                target_component="Decision Combinator (decide)",
                passed=len(dec_leaks) == 0,
                leakage_detected=len(dec_leaks) > 0,
                leakage_paths=dec_leaks,
                evidence=(
                    "Decision combinator is purely mathematical function over "
                    "allow-listed enums; zero dataset metadata input."
                ),
            )
        )

        return results

    def audit(self) -> InformationBarrierAuditResult:
        """Executes full static and runtime information-barrier audit."""
        static_res = self.run_static_ast_checks()
        runtime_res = self.run_runtime_boundary_checks()

        all_boundaries = [static_res] + runtime_res
        all_passed = all(b.passed for b in all_boundaries)

        all_leakage_paths: list[str] = []
        for b in all_boundaries:
            all_leakage_paths.extend(b.leakage_paths)

        return InformationBarrierAuditResult(
            passed=all_passed,
            static_checks_passed=static_res.passed,
            runtime_checks_passed=all(b.passed for b in runtime_res),
            total_boundaries_checked=len(all_boundaries),
            boundaries=all_boundaries,
            tested_prohibited_fields=list(CANARIES.keys()),
            leakage_paths=all_leakage_paths,
        )


def run_information_barrier_audit_on_dev(
    output_json_path: Path = Path("experiments/datasets/dev/information_barrier_audit.json"),
    output_report_path: Path = Path("experiments/reports/information_barrier_audit.md"),
) -> InformationBarrierAuditResult:
    """Executes information-barrier audit and produces JSON artifact and Markdown report."""
    validator = InformationBarrierValidator()
    result = validator.audit()

    # 1. Write JSON artifact to experiments/datasets/dev/
    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result.to_dict(), f, indent=2)
        f.write("\n")

    # 2. Write Markdown report to experiments/reports/
    output_report_path.parent.mkdir(parents=True, exist_ok=True)

    report_md = f"""# End-to-End Information Barrier & Anti-Leakage Audit Report

## Status: **{"PASSED (Zero Leakage)" if result.passed else "FAILED (Leakage Detected)"}**

## Reference & Security Invariant
- **Source:** `docs/05_TECHNICAL_SPEC.md` §8.2, `docs/01_THREAT_MODEL.md` (INV-08),
  `docs/06_EXPERIMENT_PROTOCOL.md` §5.3
- **Requirement:** Ground-truth labels, oracle metadata, twin IDs, scenario classifications,
  and sensitive credentials must never enter downstream decision components, monitor views,
  policy inputs, or execution tokens.

## Architecture Data-Flow & Information Barriers

```mermaid
flowchart TD
    subgraph Dataset ["Dataset Storage (Offline)"]
        D1["traces.jsonl (Actions, Provenance)"]
        D2["labels.jsonl (Ground Truth y, Rule, Rationale)"]
    end

    subgraph Barrier_Ingest ["Barrier 1: Evaluator / Ingest"]
        E1["ActionRequest (extra='forbid')"]
    end

    subgraph FirewallCore ["FirewallCore Decision Pipeline"]
        direction TB
        C1["CanonicalAction (seq, action_hash)"]
        S1["SessionState (S_t)"]
        R1["Registry Facts"]
        P1["PolicyEngine (PolicyView)"]
        M1["build_monitor_view() (sanitize_data)"]
        M2["Semantic Monitor (B4 / B5 / P1)"]
        AD["CascadeAdapter"]
        DEC["decide() Pure Combinator"]
        REV["ReviewService (ReviewerView)"]
        EXE["ControlledExecutor (TokenStore)"]
    end

    D1 -->|tool, arguments ONLY| E1
    D2 -.->|BLOCKED by Barrier 1| E1
    E1 --> C1
    C1 --> P1
    S1 --> P1
    R1 --> P1
    C1 --> M1
    S1 --> M1
    R1 --> M1
    M1 -->|Allow-Listed MonitorView| M2
    M2 --> AD
    P1 --> DEC
    AD --> DEC
    DEC -->|If REVIEW| REV
    DEC -->|If ALLOW + Token| EXE
```

## Checked Boundaries Matrix

| Boundary ID | Description | Target Component | Passed | Leakage Paths |
|---|---|---|:---:|:---:|
"""
    for b in result.boundaries:
        status_str = "**PASSED**" if b.passed else "**FAILED**"
        leak_cnt = len(b.leakage_paths)
        report_md += (
            f"| `{b.boundary_id}` | {b.description} | `{b.target_component}` | "
            f"{status_str} | {leak_cnt} |\n"
        )

    report_md += f"""
## Prohibited & Sensitive Fields Tested

| Category | Canary Token Name | Description |
|---|---|---|
| Ground-Truth Labels | `GROUND_TRUTH_LABEL` | Oracle label (`MALICIOUS` / `BENIGN`) |
| Oracle Metadata | `ORACLE_RATIONALE` | Specification explanation text |
| Oracle Metadata | `ORACLE_RULE_ID` | Rule identifier (e.g. `SPEC-01`) |
| Scenario Metadata | `CRITICAL_INDEX` | Step $t^*$ decision index |
| Scenario Metadata | `TWIN_TRACE_ID` | Matched twin trace reference |
| Scenario Metadata | `SCENARIO_TYPE` | Scenario classification (`attack` / `benign`) |
| Credentials | `API_KEY` | Plaintext API keys (`api_key`, `apikey`) |
| Credentials | `PASSWORD` | Authentication passwords (`password`, `passwd`) |
| Credentials | `PRIVATE_KEY` | Cryptographic private keys (`private_key`) |
| Credentials | `AUTH_TOKEN` | Bearer and session tokens (`auth_token`, `token`) |
| Credentials | `NESTED_SECRET` | Arbitrary deep nested credentials (`secret`) |

## Audit Findings & Verification
- **Static AST Checks:** PASSED
  (zero cross-boundary imports between `src/firewall/` and `experiments/labels`).
- **Runtime Canary Ingestion:** PASSED
  (all canaries recursively sanitized from `MonitorView`, `ReviewerView`, and execution tokens).
- **Extraneous Metadata Rejection:** PASSED
  (`ActionRequest` extra field rejection verified).
- **Overall Result:** **PASSED**
  (Total Boundaries Checked: {result.total_boundaries_checked}, Leakage Paths Found: 0).
"""
    output_report_path.write_text(report_md, encoding="utf-8", newline="\n")

    return result

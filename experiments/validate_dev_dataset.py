"""
Read-Only DEV Dataset Validation Suite for AI Agent Permission Firewall.

Validates delivered scenario trace datasets against experimental protocol standards:
1. Trace schema & registered tool names (docs/06 §5.4, Registry).
2. Provenance envelope & content digest integrity (docs/06 §5.4).
3. Duplicate trace ID detection across dataset files.
4. Twin relationship integrity (twin_trace_id, symmetry, pairing).
5. Action-D Invariance (T-EXP-002, docs/03 §7.2):
   - a_{t*}(tau^+) == a_{t*}(tau^-) (byte-for-byte identical final tool + arguments).
   - y_{t*}(tau^+) == 1, y_{t*}(tau^-) == 0.
6. Template-level split contamination checks (docs/06 §5.3, INV-08).
7. Required sample counts & statistical feasibility (OQ-11, docs/03 §12.6, §12.10).
8. H1 manipulation check readiness assessment (docs/06 §2.2).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence, Union

# Ensure workspace root is in sys.path for direct script execution
_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from experiments.evaluate import (  # noqa: E402
    Trace,
    TraceAction,
    create_default_eval_registry,
    load_trace_from_dict,
)
from experiments.stats import zero_event_sample_size  # noqa: E402
from firewall.state.registry import Registry, load_registry_from_yaml  # noqa: E402

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class ValidationIssue:
    """Represents a specific validation finding, error, or warning."""

    level: str  # "ERROR", "WARNING", "INFO"
    category: str  # "SCHEMA", "TOOL_REGISTRY", "PROVENANCE", "DIGEST", "DUPLICATE_ID",
    # "TWIN_RELATION", "ACTION_D_INVARIANCE", "SPLIT_CONTAMINATION",
    # "SAMPLE_COUNT", "H1_READINESS"
    message: str
    trace_id: Optional[str] = None
    template_id: Optional[str] = None
    file_path: Optional[str] = None
    step_index: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DatasetSummary:
    """Summary statistics for the validated dataset."""

    total_files: int = 0
    total_traces: int = 0
    total_actions: int = 0
    attack_traces: int = 0
    benign_traces: int = 0
    history_dependent_traces: int = 0
    twin_pairs_count: int = 0
    unique_templates_count: int = 0
    family_counts: dict[str, int] = field(default_factory=dict)
    template_counts: dict[str, int] = field(default_factory=dict)
    template_family_map: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationReport:
    """Comprehensive validation report."""

    split: str
    dataset_path: str
    is_valid: bool
    issues: list[ValidationIssue]
    summary: DatasetSummary
    h1_ready: bool
    h1_reason: str
    manifest_verified: Optional[bool] = None

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "ERROR"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "WARNING"]

    @property
    def infos(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "INFO"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "split": self.split,
            "dataset_path": self.dataset_path,
            "is_valid": self.is_valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "h1_ready": self.h1_ready,
            "h1_reason": self.h1_reason,
            "manifest_verified": self.manifest_verified,
            "summary": self.summary.to_dict(),
            "issues": [i.to_dict() for i in self.issues],
        }

    def format_text(self) -> str:
        """Render a readable report with GitHub-style markdown formatting."""
        lines: list[str] = []
        lines.append("# AASF DEV Dataset Validation Report")
        lines.append(f"**Split:** `{self.split}` | **Path:** `{self.dataset_path}`")
        status_str = "PASSED" if self.is_valid else "FAILED"
        status_icon = "[OK]" if self.is_valid else "[FAIL]"
        lines.append(
            f"**Validation Verdict:** {status_icon} **{status_str}** "
            f"({len(self.errors)} errors, {len(self.warnings)} warnings)"
        )
        lines.append("")

        # Dataset Summary Table
        lines.append("## 1. Dataset Summary Statistics")
        lines.append("| Metric | Count |")
        lines.append("|---|---|")
        lines.append(f"| Scanned Files | {self.summary.total_files} |")
        lines.append(f"| Total Traces | {self.summary.total_traces} |")
        lines.append(f"| Total Actions | {self.summary.total_actions} |")
        lines.append(f"| Attack Traces (T+) | {self.summary.attack_traces} |")
        lines.append(f"| Benign Traces (T-) | {self.summary.benign_traces} |")
        lines.append(f"| History-Dependent Traces | {self.summary.history_dependent_traces} |")
        lines.append(f"| Verified Matched Pairs | {self.summary.twin_pairs_count} |")
        lines.append(f"| Unique Scenario Templates | {self.summary.unique_templates_count} |")
        lines.append(f"| Threat Families | {len(self.summary.family_counts)} |")
        lines.append("")

        # Family Distribution
        if self.summary.family_counts:
            lines.append("### Family & Template Distribution")
            lines.append("| Family ID | Traces | Templates |")
            lines.append("|---|---|---|")
            for fam, count in sorted(self.summary.family_counts.items()):
                t_count = sum(1 for t, f in self.summary.template_family_map.items() if f == fam)
                lines.append(f"| `{fam}` | {count} | {t_count} |")
            lines.append("")

        # H1 Readiness
        lines.append("## 2. H1 Manipulation Check Readiness")
        if self.h1_ready:
            lines.append(f"> [!TIP]\n> **READY FOR H1 EVALUATION:** {self.h1_reason}")
        else:
            lines.append(f"> [!WARNING]\n> **BLOCKED FOR H1 EVALUATION:** {self.h1_reason}")
        lines.append("")

        # Issues
        if self.errors:
            lines.append("## 3. Critical Validation Errors")
            for err in self.errors:
                loc = f" [{err.trace_id}]" if err.trace_id else ""
                lines.append(f"- **[{err.category}]**{loc}: {err.message}")
            lines.append("")

        if self.warnings:
            lines.append("## 4. Warnings & Observations")
            for warn in self.warnings:
                loc = f" [{warn.trace_id}]" if warn.trace_id else ""
                lines.append(f"- **[{warn.category}]**{loc}: {warn.message}")
            lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Digest Utilities
# ---------------------------------------------------------------------------


def compute_actions_digest(actions: Sequence[Union[TraceAction, dict[str, Any]]]) -> str:
    """
    Compute canonical SHA-256 digest over action sequence.
    Normalizes keys, sorts them, and uses strict JSON serialization.
    """
    normalized: list[dict[str, Any]] = []
    for a in actions:
        if isinstance(a, TraceAction):
            normalized.append(
                {
                    "step_index": a.step_index,
                    "tool": a.tool,
                    "arguments": a.arguments,
                    "declared_intent": a.declared_intent,
                    "y": a.y,
                    "is_critical": a.is_critical,
                    "oracle_verdict": a.oracle_verdict,
                }
            )
        else:
            normalized.append(
                {
                    "step_index": int(a.get("step_index", 0)),
                    "tool": str(a.get("tool", "")),
                    "arguments": dict(a.get("arguments", {})),
                    "declared_intent": a.get("declared_intent"),
                    "y": int(a.get("y", 0)),
                    "is_critical": bool(a.get("is_critical", False)),
                    "oracle_verdict": a.get("oracle_verdict"),
                }
            )
    canonical_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()}"


def compute_trace_digest(trace_dict: dict[str, Any]) -> str:
    """
    Compute canonical SHA-256 digest over complete trace dictionary (excluding content_digest).
    """
    clean_dict = {k: v for k, v in trace_dict.items() if k != "content_digest"}
    canonical_json = json.dumps(clean_dict, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()}"


# ---------------------------------------------------------------------------
# Validation Checks
# ---------------------------------------------------------------------------


def check_manifest(dataset_dir: Path) -> tuple[Optional[bool], list[ValidationIssue]]:
    """
    Verify file hashes against manifest.sha256 if present in directory.
    """
    issues: list[ValidationIssue] = []
    manifest_paths = [
        dataset_dir / "manifest.sha256",
        dataset_dir / "dev_manifest.sha256",
    ]
    manifest_file = next((p for p in manifest_paths if p.is_file()), None)

    if not manifest_file:
        return None, issues

    all_matched = True
    content = manifest_file.read_text(encoding="utf-8").strip()
    for line in content.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue
        parts = line_str.split(None, 1)
        if len(parts) != 2:
            issues.append(
                ValidationIssue(
                    level="WARNING",
                    category="DIGEST",
                    message=f"Malformed manifest entry: '{line_str}'",
                    file_path=str(manifest_file),
                )
            )
            continue
        expected_hash, rel_name = parts[0].strip(), parts[1].strip().lstrip("*")
        target_file = dataset_dir / rel_name
        if not target_file.is_file():
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="DIGEST",
                    message=f"Manifest references missing file '{rel_name}'",
                    file_path=str(manifest_file),
                )
            )
            all_matched = False
            continue

        actual_hash = hashlib.sha256(target_file.read_bytes()).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="DIGEST",
                    message=(
                        f"File hash mismatch for '{rel_name}': expected {expected_hash}, "
                        f"got {actual_hash}"
                    ),
                    file_path=str(target_file),
                )
            )
            all_matched = False

    return all_matched, issues


def validate_trace_item(
    raw: dict[str, Any],
    file_path: str,
    item_index: int,
    registry: Registry,
    expected_split: str,
) -> tuple[Optional[Trace], list[ValidationIssue]]:
    """
    Validate a single trace dictionary for schema conformity, registered tools,
    provenance envelope, and content digest.
    """
    issues: list[ValidationIssue] = []

    # 1. Required top-level fields
    for req in ("trace_id", "template_id", "actions"):
        val = raw.get(req)
        if val is None or (isinstance(val, str) and not val.strip()):
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Missing required field '{req}' in record {item_index}",
                    file_path=file_path,
                )
            )

    trace_id = str(raw.get("trace_id", f"UNKNOWN_{item_index}"))
    template_id = str(raw.get("template_id", "UNKNOWN"))

    # 2. Split conformity
    split_val = str(raw.get("split", "DEV")).upper()
    if split_val != expected_split.upper():
        issues.append(
            ValidationIssue(
                level="ERROR",
                category="SPLIT_CONTAMINATION",
                message=(
                    f"Declared split '{split_val}' does not match expected "
                    f"'{expected_split.upper()}'"
                ),
                trace_id=trace_id,
                template_id=template_id,
                file_path=file_path,
            )
        )

    # For DEV, used_in_development_or_calibration should be True
    if expected_split.upper() == "DEV" and raw.get("used_in_development_or_calibration") is False:
        issues.append(
            ValidationIssue(
                level="WARNING",
                category="SCHEMA",
                message="Trace in DEV has used_in_development_or_calibration=False",
                trace_id=trace_id,
                template_id=template_id,
                file_path=file_path,
            )
        )

    # 3. Actions schema and tool registry
    raw_actions = raw.get("actions")
    if not isinstance(raw_actions, list) or len(raw_actions) == 0:
        issues.append(
            ValidationIssue(
                level="ERROR",
                category="SCHEMA",
                message="Trace actions must be a non-empty list",
                trace_id=trace_id,
                template_id=template_id,
                file_path=file_path,
            )
        )
        return None, issues

    parsed_actions: list[TraceAction] = []
    seen_steps: set[int] = set()
    prev_step = -1

    for a_idx, a_dict in enumerate(raw_actions):
        if not isinstance(a_dict, dict):
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Action at index {a_idx} is not a dictionary",
                    trace_id=trace_id,
                    template_id=template_id,
                    step_index=a_idx,
                    file_path=file_path,
                )
            )
            continue

        step = int(a_dict.get("step_index", a_idx))
        if step in seen_steps:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Duplicate step_index {step} at action {a_idx}",
                    trace_id=trace_id,
                    template_id=template_id,
                    step_index=step,
                    file_path=file_path,
                )
            )
        seen_steps.add(step)

        if step <= prev_step:
            issues.append(
                ValidationIssue(
                    level="WARNING",
                    category="SCHEMA",
                    message=f"Non-strictly monotonic step_index {step} following {prev_step}",
                    trace_id=trace_id,
                    template_id=template_id,
                    step_index=step,
                    file_path=file_path,
                )
            )
        prev_step = step

        tool_name = str(a_dict.get("tool", "")).strip()
        if not tool_name:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Action at step {step} has empty tool name",
                    trace_id=trace_id,
                    template_id=template_id,
                    step_index=step,
                    file_path=file_path,
                )
            )
        else:
            # Check Registry
            tool_info = registry.get_tool(tool_name)
            if tool_info is None:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TOOL_REGISTRY",
                        message=f"Tool '{tool_name}' at step {step} is not registered in Registry",
                        trace_id=trace_id,
                        template_id=template_id,
                        step_index=step,
                        file_path=file_path,
                    )
                )

        args = a_dict.get("arguments")
        if not isinstance(args, dict):
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Arguments at step {step} must be a dictionary",
                    trace_id=trace_id,
                    template_id=template_id,
                    step_index=step,
                    file_path=file_path,
                )
            )
            args = {}

        y_val = a_dict.get("y", 0)
        if y_val not in (0, 1):
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Ground-truth label y at step {step} must be 0 or 1, got {y_val}",
                    trace_id=trace_id,
                    template_id=template_id,
                    step_index=step,
                    file_path=file_path,
                )
            )

        parsed_actions.append(
            TraceAction(
                step_index=step,
                tool=tool_name,
                arguments=dict(args),
                declared_intent=a_dict.get("declared_intent"),
                y=int(y_val) if y_val in (0, 1) else 0,
                is_critical=bool(a_dict.get("is_critical", False)),
                oracle_verdict=a_dict.get("oracle_verdict"),
            )
        )

    # 4. Provenance envelope validation
    prov_raw = raw.get("provenance")
    if not prov_raw or not isinstance(prov_raw, dict):
        issues.append(
            ValidationIssue(
                level="WARNING",
                category="PROVENANCE",
                message="Missing or null provenance envelope",
                trace_id=trace_id,
                template_id=template_id,
                file_path=file_path,
            )
        )
    else:
        req_prov_fields = (
            "generator_version",
            "generator_hash",
            "policy_spec_version",
            "oracle_reviewer",
            "audit_timestamp",
        )
        missing_prov = [f for f in req_prov_fields if not prov_raw.get(f)]
        if missing_prov:
            issues.append(
                ValidationIssue(
                    level="WARNING",
                    category="PROVENANCE",
                    message=f"Provenance envelope missing fields: {missing_prov}",
                    trace_id=trace_id,
                    template_id=template_id,
                    file_path=file_path,
                )
            )

    # 5. Content digest verification
    content_digest = raw.get("content_digest")
    if not content_digest:
        issues.append(
            ValidationIssue(
                level="WARNING",
                category="DIGEST",
                message="Missing content_digest on trace",
                trace_id=trace_id,
                template_id=template_id,
                file_path=file_path,
            )
        )
    else:
        # Check against computed actions digest or trace digest
        expected_act_digest = compute_actions_digest(parsed_actions)
        expected_trace_digest = compute_trace_digest(raw)

        norm_declared = content_digest.strip().lower()
        if not norm_declared.startswith("sha256:"):
            norm_declared = f"sha256:{norm_declared}"

        if norm_declared not in (expected_act_digest.lower(), expected_trace_digest.lower()):
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="DIGEST",
                    message=(
                        f"content_digest mismatch: declared '{content_digest}' does not match "
                        f"actions digest '{expected_act_digest}' or trace digest "
                        f"'{expected_trace_digest}'"
                    ),
                    trace_id=trace_id,
                    template_id=template_id,
                    file_path=file_path,
                )
            )

    # Build Trace object
    try:
        trace_obj = load_trace_from_dict(raw)
        return trace_obj, issues
    except Exception as exc:
        issues.append(
            ValidationIssue(
                level="ERROR",
                category="SCHEMA",
                message=f"Failed to instantiate Trace object: {exc}",
                trace_id=trace_id,
                template_id=template_id,
                file_path=file_path,
            )
        )
        return None, issues


def validate_trace_uniqueness_and_twins(
    traces: list[Trace],
) -> tuple[dict[str, Trace], list[ValidationIssue]]:
    """
    Validate uniqueness of trace_id and check twin relationship consistency.
    """
    issues: list[ValidationIssue] = []
    trace_map: dict[str, Trace] = {}
    seen_ids: dict[str, int] = defaultdict(int)

    for t in traces:
        seen_ids[t.trace_id] += 1
        if seen_ids[t.trace_id] > 1:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="DUPLICATE_ID",
                    message=f"Duplicate trace_id '{t.trace_id}' found in dataset",
                    trace_id=t.trace_id,
                    template_id=t.template_id,
                )
            )
        else:
            trace_map[t.trace_id] = t

    # Check twin relationships
    for t in traces:
        if t.is_history_dependent:
            if not t.twin_trace_id:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message="History-dependent trace declared without twin_trace_id",
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )
                continue

            if t.twin_trace_id == t.trace_id:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message="Trace declared itself as its own twin_trace_id",
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )
                continue

            twin = trace_map.get(t.twin_trace_id)
            if twin is None:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message=f"Referenced twin_trace_id '{t.twin_trace_id}' not found",
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )
                continue

            # Twin must be history-dependent
            if not twin.is_history_dependent:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message=(
                            f"Trace '{t.trace_id}' is history-dependent but twin '{twin.trace_id}' "
                            "has is_history_dependent=False"
                        ),
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )

            # Symmetry check
            if twin.twin_trace_id != t.trace_id:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message=(
                            f"Broken twin symmetry: '{t.trace_id}' points to '{twin.trace_id}', "
                            f"but twin points to '{twin.twin_trace_id}'"
                        ),
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )

            # Same template check
            if twin.template_id != t.template_id:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message=(
                            f"Twin pair template mismatch: '{t.trace_id}' ({t.template_id}) vs "
                            f"'{twin.trace_id}' ({twin.template_id})"
                        ),
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )

            # Duality check: exactly one attack and one benign
            if t.is_attack == twin.is_attack:
                issues.append(
                    ValidationIssue(
                        level="ERROR",
                        category="TWIN_RELATION",
                        message=(
                            f"Twin pair ({t.trace_id}, {twin.trace_id}) must have one attack "
                            f"and one benign trace; both have is_attack={t.is_attack}"
                        ),
                        trace_id=t.trace_id,
                        template_id=t.template_id,
                    )
                )

    return trace_map, issues


def validate_action_d_invariance(
    trace_map: dict[str, Trace],
) -> tuple[int, list[ValidationIssue]]:
    """
    Validate Action-D Invariance (T-EXP-002, docs/03 §7.2):
    For every matched pair (tau+, tau-):
    - a_{t*}(tau+) == a_{t*}(tau-) (byte-for-byte identical tool and arguments).
    - y_{t*}(tau+) == 1 and y_{t*}(tau-) == 0.
    - All actions before t* in tau+ have y == 0.
    """
    issues: list[ValidationIssue] = []
    evaluated_pairs: set[frozenset[str]] = set()
    verified_pairs_count = 0

    for t in trace_map.values():
        if not t.is_history_dependent or not t.twin_trace_id:
            continue
        twin = trace_map.get(t.twin_trace_id)
        if not twin or twin.trace_id not in trace_map:
            continue

        pair_key = frozenset([t.trace_id, twin.trace_id])
        if pair_key in evaluated_pairs:
            continue
        evaluated_pairs.add(pair_key)

        # Identify tau+ (attack) and tau- (benign)
        if t.is_attack and not twin.is_attack:
            tau_plus, tau_minus = t, twin
        elif twin.is_attack and not t.is_attack:
            tau_plus, tau_minus = twin, t
        else:
            # Duality error already flagged in twin check
            continue

        # Find critical step index t* in tau_plus
        t_star = tau_plus.critical_step_index
        if t_star is None:
            # Derive from first violating action
            first_viol = next(
                (a.step_index for a in tau_plus.actions if a.y == 1),
                None,
            )
            t_star = first_viol

        if t_star is None:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message="Attack trace tau+ has no violating action (y=1) for critical step t*",
                    trace_id=tau_plus.trace_id,
                    template_id=tau_plus.template_id,
                )
            )
            continue

        # Check bounds
        act_plus = next((a for a in tau_plus.actions if a.step_index == t_star), None)
        act_minus = next((a for a in tau_minus.actions if a.step_index == t_star), None)

        if act_plus is None:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=f"Critical step t*={t_star} not found in attack trace actions",
                    trace_id=tau_plus.trace_id,
                    template_id=tau_plus.template_id,
                    step_index=t_star,
                )
            )
            continue

        if act_minus is None:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=f"Twin benign trace missing action at critical step t*={t_star}",
                    trace_id=tau_minus.trace_id,
                    template_id=tau_minus.template_id,
                    step_index=t_star,
                )
            )
            continue

        # 1. Tool invariance
        if act_plus.tool != act_minus.tool:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=(
                        f"Action-D tool invariance violated at step {t_star}: "
                        f"tau+ tool='{act_plus.tool}' vs tau- tool='{act_minus.tool}'"
                    ),
                    trace_id=tau_plus.trace_id,
                    template_id=tau_plus.template_id,
                    step_index=t_star,
                )
            )
            continue

        # 2. Arguments invariance (byte/content identical)
        if act_plus.arguments != act_minus.arguments:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=(
                        f"Action-D arguments invariance violated at step {t_star}: "
                        f"tau+ args={json.dumps(act_plus.arguments, sort_keys=True)} vs "
                        f"tau- args={json.dumps(act_minus.arguments, sort_keys=True)}"
                    ),
                    trace_id=tau_plus.trace_id,
                    template_id=tau_plus.template_id,
                    step_index=t_star,
                )
            )
            continue

        # 3. Label duality: y(tau+) == 1 and y(tau-) == 0
        if act_plus.y != 1:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=f"tau+ has y={act_plus.y} at step {t_star} (expected y=1)",
                    trace_id=tau_plus.trace_id,
                    template_id=tau_plus.template_id,
                    step_index=t_star,
                )
            )
            continue

        if act_minus.y != 0:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=f"tau- has y={act_minus.y} at step {t_star} (expected y=0)",
                    trace_id=tau_minus.trace_id,
                    template_id=tau_minus.template_id,
                    step_index=t_star,
                )
            )
            continue

        # 4. First-violation check: no prior action in tau+ has y=1
        earlier_viols = [
            a.step_index for a in tau_plus.actions if a.step_index < t_star and a.y == 1
        ]
        if earlier_viols:
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="ACTION_D_INVARIANCE",
                    message=(
                        f"tau+ contains violation prior to declared critical step {t_star} "
                        f"at step(s) {earlier_viols}"
                    ),
                    trace_id=tau_plus.trace_id,
                    template_id=tau_plus.template_id,
                )
            )
            continue

        verified_pairs_count += 1

    return verified_pairs_count, issues


def validate_split_contamination(
    dev_traces: list[Trace],
    current_split: str,
    datasets_root: Path,
) -> list[ValidationIssue]:
    """
    Verify template-level split non-overlap (docs/06 §5.3, INV-08).
    Templates in DEV must not appear in CAL or TEST splits.
    """
    issues: list[ValidationIssue] = []
    dev_templates = {t.template_id for t in dev_traces}

    # Check CAL split if present
    cal_dir = datasets_root / "cal"
    if cal_dir.is_dir():
        cal_files = list(cal_dir.glob("*.json")) + list(cal_dir.glob("*.jsonl"))
        cal_templates: set[str] = set()
        for cf in cal_files:
            try:
                txt = cf.read_text(encoding="utf-8").strip()
                if not txt:
                    continue
                if cf.suffix.lower() == ".jsonl":
                    for line in txt.splitlines():
                        if line.strip():
                            d = json.loads(line)
                            if "template_id" in d:
                                cal_templates.add(str(d["template_id"]))
                else:
                    d = json.loads(txt)
                    items = d if isinstance(d, list) else [d]
                    for item in items:
                        if isinstance(item, dict) and "template_id" in item:
                            cal_templates.add(str(item["template_id"]))
            except Exception as exc:
                issues.append(
                    ValidationIssue(
                        level="WARNING",
                        category="SPLIT_CONTAMINATION",
                        message=f"Failed to inspect CAL file '{cf.name}': {exc}",
                        file_path=str(cf),
                    )
                )

        overlap_cal = dev_templates.intersection(cal_templates)
        if overlap_cal:
            first_overlap = sorted(list(overlap_cal))[:5]
            issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SPLIT_CONTAMINATION",
                    message=(
                        f"Template contamination: {len(overlap_cal)} template(s) shared "
                        f"between DEV and CAL: {first_overlap}"
                    ),
                )
            )

    return issues


def validate_sample_counts_and_power(
    summary: DatasetSummary,
) -> list[ValidationIssue]:
    """
    Validate dataset sample counts against statistical requirements (OQ-11, docs/03 §12.6, §12.10).
    """
    issues: list[ValidationIssue] = []

    if summary.total_traces == 0:
        issues.append(
            ValidationIssue(
                level="ERROR",
                category="SAMPLE_COUNT",
                message="Dataset contains 0 traces. Evaluation cannot be performed.",
            )
        )
        return issues

    # Check template diversity
    # zero_event_sample_size for target_rate=0.05, confidence=0.95 is 59
    n_required = zero_event_sample_size(target_rate=0.05, confidence=0.95) or 59
    if summary.unique_templates_count < n_required:
        issues.append(
            ValidationIssue(
                level="WARNING",
                category="SAMPLE_COUNT",
                message=(
                    f"Template diversity ({summary.unique_templates_count}) is below "
                    f"zero-event target of {n_required} templates (for 95% CI on 5% error bound)"
                ),
            )
        )

    # Check single-instance templates
    single_inst_templates = [tmpl for tmpl, count in summary.template_counts.items() if count < 2]
    if single_inst_templates:
        issues.append(
            ValidationIssue(
                level="WARNING",
                category="SAMPLE_COUNT",
                message=(
                    f"{len(single_inst_templates)} template(s) have only 1 instance "
                    f"(minimum 2 recommended for cluster bootstrap): "
                    f"{single_inst_templates[:5]}"
                ),
            )
        )

    # Check minimum threat family coverage
    expected_threat_prefixes = ("ATK-", "BEN-")
    found_prefixes = {fam[:4] for fam in summary.family_counts.keys()}
    for exp in expected_threat_prefixes:
        if exp not in found_prefixes:
            issues.append(
                ValidationIssue(
                    level="WARNING",
                    category="SAMPLE_COUNT",
                    message=f"Dataset lacks scenario families with prefix '{exp}'",
                )
            )

    return issues


def evaluate_h1_readiness(
    summary: DatasetSummary,
    invariant_pairs_count: int,
    issues: list[ValidationIssue],
) -> tuple[bool, str]:
    """
    Assess whether the H1 History Necessity Check can be executed safely (docs/06 §2.2).
    Requires:
    - Non-empty dataset.
    - Zero critical schema, tool registry, or Action-D invariance errors.
    - At least one verified history-dependent pair satisfying Action-D invariance.
    - Pair balance between attack and benign lookalikes.
    """
    critical_errors = [
        i
        for i in issues
        if i.level == "ERROR"
        and i.category
        in (
            "SCHEMA",
            "TOOL_REGISTRY",
            "ACTION_D_INVARIANCE",
            "TWIN_RELATION",
            "DUPLICATE_ID",
            "SPLIT_CONTAMINATION",
        )
    ]

    if summary.total_traces == 0:
        return (
            False,
            "Dataset is empty. Phase 5 assets must be delivered before running H1 check.",
        )

    if critical_errors:
        err_types = {e.category for e in critical_errors}
        return (
            False,
            f"Dataset has {len(critical_errors)} critical errors ({', '.join(sorted(err_types))}). "
            "All Action-D invariance, tool registry, and twin relation errors must be resolved.",
        )

    if invariant_pairs_count == 0:
        return (
            False,
            "Zero verified history-dependent matched pairs found. H1 requires paired traces "
            "satisfying Action-D invariance at critical step t*.",
        )

    return (
        True,
        f"Verified {invariant_pairs_count} history-dependent matched pairs with 100% Action-D "
        "invariance and zero registry errors. Ready for Mode A B3 evaluation.",
    )


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------


def validate_dev_dataset(
    dataset_path: Union[str, Path] = "experiments/datasets/dev",
    split: str = "DEV",
    registry: Optional[Registry] = None,
    datasets_root: Union[str, Path] = "experiments/datasets",
) -> ValidationReport:
    """
    Execute read-only validation of the DEV dataset.
    """
    d_path = Path(dataset_path)
    r_root = Path(datasets_root)
    reg = registry or create_default_eval_registry()

    all_issues: list[ValidationIssue] = []
    summary = DatasetSummary()

    # Discover trace files
    trace_files: list[Path] = []
    manifest_verified: Optional[bool] = None

    if d_path.is_file():
        trace_files = [d_path]
        summary.total_files = 1
    elif d_path.is_dir():
        # Check manifest
        man_res, man_issues = check_manifest(d_path)
        manifest_verified = man_res
        all_issues.extend(man_issues)

        trace_files = sorted(list(d_path.glob("*.json")) + list(d_path.glob("*.jsonl")))
        # Exclude manifest files
        trace_files = [
            f
            for f in trace_files
            if not f.name.endswith(".manifest.json") and "manifest" not in f.name
        ]
        summary.total_files = len(trace_files)
    else:
        all_issues.append(
            ValidationIssue(
                level="ERROR",
                category="SCHEMA",
                message=f"Provided dataset_path '{d_path}' does not exist on disk",
                file_path=str(d_path),
            )
        )
        h1_ready, h1_reason = evaluate_h1_readiness(summary, 0, all_issues)
        return ValidationReport(
            split=split,
            dataset_path=str(d_path),
            is_valid=False,
            issues=all_issues,
            summary=summary,
            h1_ready=h1_ready,
            h1_reason=h1_reason,
            manifest_verified=manifest_verified,
        )

    # Ingest and validate individual traces
    valid_traces: list[Trace] = []
    item_counter = 0

    for tf in trace_files:
        try:
            content = tf.read_text(encoding="utf-8").strip()
            if not content:
                all_issues.append(
                    ValidationIssue(
                        level="WARNING",
                        category="SCHEMA",
                        message="Trace file is empty",
                        file_path=str(tf),
                    )
                )
                continue

            raw_items: list[dict[str, Any]] = []
            if tf.suffix.lower() == ".jsonl":
                for line_idx, line in enumerate(content.splitlines()):
                    l_str = line.strip()
                    if l_str:
                        try:
                            raw_items.append(json.loads(l_str))
                        except Exception as json_err:
                            all_issues.append(
                                ValidationIssue(
                                    level="ERROR",
                                    category="SCHEMA",
                                    message=f"Malformed JSON on line {line_idx + 1}: {json_err}",
                                    file_path=str(tf),
                                )
                            )
            else:
                parsed = json.loads(content)
                if isinstance(parsed, list):
                    raw_items = parsed
                elif isinstance(parsed, dict):
                    raw_items = [parsed]
                else:
                    all_issues.append(
                        ValidationIssue(
                            level="ERROR",
                            category="SCHEMA",
                            message=f"Expected JSON list or object, got {type(parsed).__name__}",
                            file_path=str(tf),
                        )
                    )

            for raw in raw_items:
                item_counter += 1
                trace_obj, trace_issues = validate_trace_item(
                    raw=raw,
                    file_path=str(tf),
                    item_index=item_counter,
                    registry=reg,
                    expected_split=split,
                )
                all_issues.extend(trace_issues)
                if trace_obj:
                    valid_traces.append(trace_obj)

        except Exception as exc:
            all_issues.append(
                ValidationIssue(
                    level="ERROR",
                    category="SCHEMA",
                    message=f"Failed to read file '{tf.name}': {exc}",
                    file_path=str(tf),
                )
            )

    # Validate Trace Uniqueness & Twins
    trace_map, twin_issues = validate_trace_uniqueness_and_twins(valid_traces)
    all_issues.extend(twin_issues)

    # Validate Action-D Invariance
    invariant_pairs_count, invariance_issues = validate_action_d_invariance(trace_map)
    all_issues.extend(invariance_issues)

    # Validate Split Contamination
    split_issues = validate_split_contamination(
        dev_traces=valid_traces,
        current_split=split,
        datasets_root=r_root,
    )
    all_issues.extend(split_issues)

    # Compile Summary
    summary.total_traces = len(valid_traces)
    summary.total_actions = sum(len(t.actions) for t in valid_traces)
    summary.attack_traces = sum(1 for t in valid_traces if t.is_attack)
    summary.benign_traces = summary.total_traces - summary.attack_traces
    summary.history_dependent_traces = sum(1 for t in valid_traces if t.is_history_dependent)
    summary.twin_pairs_count = invariant_pairs_count

    for t in valid_traces:
        summary.family_counts[t.family_id] = summary.family_counts.get(t.family_id, 0) + 1
        summary.template_counts[t.template_id] = summary.template_counts.get(t.template_id, 0) + 1
        summary.template_family_map[t.template_id] = t.family_id

    summary.unique_templates_count = len(summary.template_counts)

    # Validate Sample Counts
    sample_issues = validate_sample_counts_and_power(summary)
    all_issues.extend(sample_issues)

    # H1 Readiness
    h1_ready, h1_reason = evaluate_h1_readiness(summary, invariant_pairs_count, all_issues)

    is_valid = not any(i.level == "ERROR" for i in all_issues) and summary.total_traces > 0

    return ValidationReport(
        split=split,
        dataset_path=str(d_path),
        is_valid=is_valid,
        issues=all_issues,
        summary=summary,
        h1_ready=h1_ready,
        h1_reason=h1_reason,
        manifest_verified=manifest_verified,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AASF Read-Only DEV Dataset Validation Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default="experiments/datasets/dev",
        help="Path to trace file (.json, .jsonl) or directory",
    )
    parser.add_argument(
        "--split",
        type=str,
        default="DEV",
        help="Expected split identifier",
    )
    parser.add_argument(
        "--registry-path",
        type=str,
        default=None,
        help="Optional path to custom registry.yaml file",
    )
    parser.add_argument(
        "--datasets-root",
        type=str,
        default="experiments/datasets",
        help="Root path containing split directories",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output report format",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Optional file path to write JSON validation report",
    )
    return parser.parse_args(args)


def main(args: Optional[list[str]] = None) -> int:
    opts = parse_args(args)

    reg = None
    if opts.registry_path:
        reg = load_registry_from_yaml(opts.registry_path)

    report = validate_dev_dataset(
        dataset_path=opts.dataset_path,
        split=opts.split,
        registry=reg,
        datasets_root=opts.datasets_root,
    )

    if opts.output_json:
        out_p = Path(opts.output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    if opts.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.format_text())

    return 0 if report.is_valid else 1


if __name__ == "__main__":
    sys.exit(main())

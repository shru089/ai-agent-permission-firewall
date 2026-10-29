"""
Policy rule models and three-valued condition evaluator for AI Agent Permission Firewall.
Source: 03_MATHEMATICAL_MODEL_AND_METRICS.md §3, 05_TECHNICAL_SPEC.md §7.2
"""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from firewall.contracts.enums import Classification, PolicyVerdict, ToolClass, Zone
from firewall.contracts.models import CanonicalAction, SessionState
from firewall.state.registry import Registry


class TriBool(str, Enum):
    """Three-valued logic state (Kleene logic)."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class Condition(BaseModel):
    """
    Condition for a policy rule.
    Supports state, arg, and registry sources with standard comparison operators.
    Source: 05_TECHNICAL_SPEC.md §7.2
    """

    state: Optional[str] = None
    arg: Optional[str] = None
    registry: Optional[str] = None
    op: str = "eq"  # "eq" | "neq" | "in" | "gt" | "lt" | "exists"
    value: Optional[Any] = None

    model_config = ConfigDict(extra="forbid")

    def evaluate(
        self,
        action: CanonicalAction,
        state: SessionState,
        registry: Registry,
    ) -> tuple[TriBool, Optional[str]]:
        """
        Evaluate condition returning (TriBool, missing_field_path_if_unknown).
        """
        # 1. Resolve field value
        target_field = ""
        val: Any = None
        is_unknown = False

        if self.state is not None:
            target_field = f"state.{self.state}"
            val, is_unknown = _resolve_state_path(state, self.state)
        elif self.arg is not None:
            target_field = f"arg.{self.arg}"
            if self.arg not in action.arguments:
                is_unknown = True
            else:
                val = action.arguments[self.arg]
        elif self.registry is not None:
            target_field = f"registry.{self.registry}"
            val, is_unknown = _resolve_registry_path(registry, action, self.registry)
        else:
            return TriBool.UNKNOWN, "unspecified_source"

        if is_unknown:
            # Special case: 'exists' check
            if self.op == "exists":
                return (TriBool.FALSE if not self.value else TriBool.TRUE), None
            return TriBool.UNKNOWN, target_field

        # 2. Evaluate operator with resolved value
        res = _evaluate_op(val, self.op, self.value)
        return res, (target_field if res == TriBool.UNKNOWN else None)


def _resolve_state_path(state: SessionState, path: str) -> tuple[Any, bool]:
    """
    Resolve dot-separated path into SessionState.
    Returns (value, is_unknown).
    """
    parts = path.split(".")
    curr: Any = state

    for i, part in enumerate(parts):
        if curr is None:
            return None, True

        if isinstance(curr, SessionState):
            if part == "bound_resource":
                curr = curr.bound_resource
            elif part == "destination":
                curr = curr.destination
            elif part == "job_created":
                curr = curr.job_created
            elif part == "egress_counters":
                curr = curr.egress_counters
            elif part == "anomalies":
                curr = curr.anomalies
            elif part == "selected_resources":
                curr = curr.selected_resources
            elif part == "jobs":
                curr = curr.jobs
            else:
                return None, True
        elif isinstance(curr, dict):
            if part in curr:
                curr = curr[part]
            else:
                # Egress counter zone lookup default if missing
                if i == 1 and parts[0] == "egress_counters":
                    return 0, False
                return None, True
        elif hasattr(curr, part):
            curr = getattr(curr, part)
        else:
            return None, True

        # Check for explicit UNKNOWN classification/zone
        if isinstance(curr, Classification) and curr == Classification.UNKNOWN:
            return None, True
        if isinstance(curr, Zone) and curr == Zone.UNKNOWN:
            return None, True

    if curr is None:
        return None, True
    return curr, False


def _resolve_registry_path(
    registry: Registry, action: CanonicalAction, path: str
) -> tuple[Any, bool]:
    """Resolve registry path for named action entities."""
    parts = path.split(".")
    if len(parts) >= 2 and parts[0] == "destination":
        dest_ref = action.arguments.get("destination_ref")
        if not dest_ref:
            return None, True
        dest = registry.get_destination(str(dest_ref))
        if dest is None or dest.zone == Zone.UNKNOWN:
            return None, True
        if parts[1] == "zone":
            return dest.zone, False
    return None, True


def _evaluate_op(val: Any, op: str, expected: Any) -> TriBool:
    """Evaluate comparison operator."""
    if op == "exists":
        exists = val is not None
        return TriBool.TRUE if bool(expected) == exists else TriBool.FALSE

    # Normalization for string and enum values
    val_norm = val.value if hasattr(val, "value") else val
    exp_norm = expected.value if hasattr(expected, "value") else expected

    try:
        if op == "eq":
            return TriBool.TRUE if val_norm == exp_norm else TriBool.FALSE
        elif op == "neq":
            return TriBool.TRUE if val_norm != exp_norm else TriBool.FALSE
        elif op == "in":
            if isinstance(exp_norm, (list, tuple, set)):
                items = [x.value if hasattr(x, "value") else x for x in exp_norm]
                return TriBool.TRUE if val_norm in items else TriBool.FALSE
            return TriBool.UNKNOWN
        elif op == "gt":
            return TriBool.TRUE if val_norm > exp_norm else TriBool.FALSE
        elif op == "lt":
            return TriBool.TRUE if val_norm < exp_norm else TriBool.FALSE
    except TypeError:
        return TriBool.UNKNOWN

    return TriBool.UNKNOWN


class PolicyRule(BaseModel):
    """
    Deterministic policy rule definition.
    Source: 05_TECHNICAL_SPEC.md §7.2
    """

    id: str
    effect: PolicyVerdict  # PolicyVerdict.PROHIBIT | PolicyVerdict.PERMIT
    tool: Optional[str] = None
    tool_class: Optional[ToolClass] = None
    when: list[Condition] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    def applies_to(self, action: CanonicalAction, tool_class: Optional[ToolClass]) -> bool:
        """Check if rule applies to the specified tool or tool_class."""
        if self.tool is not None and self.tool != action.tool:
            return False
        if self.tool_class is not None and self.tool_class != tool_class:
            return False
        return True

    def evaluate(
        self,
        action: CanonicalAction,
        state: SessionState,
        registry: Registry,
    ) -> tuple[TriBool, list[str]]:
        """
        Evaluate rule conditions.
        Returns:
            (TriBool, missing_fields):
            - TRUE: MATCH (all conditions TRUE)
            - FALSE: NO_MATCH (at least one condition FALSE)
            - UNKNOWN: MAYBE (no FALSE, at least one condition UNKNOWN)
        """
        if not self.when:
            return TriBool.TRUE, []

        has_unknown = False
        missing_fields: list[str] = []

        for cond in self.when:
            res, missing = cond.evaluate(action, state, registry)
            if res == TriBool.FALSE:
                return TriBool.FALSE, []
            elif res == TriBool.UNKNOWN:
                has_unknown = True
                if missing:
                    missing_fields.append(missing)

        if has_unknown:
            return TriBool.UNKNOWN, missing_fields
        return TriBool.TRUE, []

"""
Deterministic Three-Valued Policy Engine (C3) for AI Agent Permission Firewall.
Evaluates:
    V_t = PolicyEngine.evaluate(action, state, registry)
Source: 03_MATHEMATICAL_MODEL_AND_METRICS.md §3, 05_TECHNICAL_SPEC.md §7.2
"""

import hashlib
from typing import Sequence

from firewall.contracts.enums import Classification, PolicyVerdict, ToolClass, Zone
from firewall.contracts.hashing import canonical_json
from firewall.contracts.models import CanonicalAction, PolicyResult, SessionState
from firewall.policy.rules import Condition, PolicyRule, TriBool
from firewall.state.registry import Registry


class PolicyEngine:
    """
    Deterministic Three-Valued Policy Evaluator.
    Guarantees:
    - Determinism: V_t depends only on (action, state, rules, registry)
    - Prohibit dominance: matched or maybe-matched PROHIBIT dominates PERMIT
    - Rule-order independence
    - Evidence monotonicity
    """

    def __init__(self, rules: Sequence[PolicyRule], version: str = "0.1.0") -> None:
        self.rules = list(rules)
        self.version = version
        self._policy_hash = self._compute_policy_hash()

    @property
    def policy_hash(self) -> str:
        return self._policy_hash

    def _compute_policy_hash(self) -> str:
        rule_dumps = [r.model_dump() for r in self.rules]
        canonical_bytes = canonical_json(rule_dumps, reject_floats=False)
        return hashlib.sha256(canonical_bytes).hexdigest()

    def evaluate(
        self,
        action: CanonicalAction,
        state: SessionState,
        registry: Registry,
    ) -> PolicyResult:
        """
        Evaluate applicable rules against canonical action, session state, and registry facts.
        Precedence:
        1. Any applicable PROHIBIT is MATCH -> PROHIBIT
        2. Else if any applicable PROHIBIT is MAYBE -> EVIDENCE_MISSING
        3. Else if any applicable PERMIT is MATCH -> PERMIT
        4. Otherwise -> UNDETERMINED
        """
        tool_info = registry.get_tool(action.tool)
        tool_class = tool_info.tool_class if tool_info else None

        matched_prohibits: list[str] = []
        maybe_prohibits: list[str] = []
        missing_fields: list[str] = []
        matched_permits: list[str] = []
        maybe_permits: list[str] = []

        registry_hash = hashlib.sha256(
            canonical_json(registry.snapshot(), reject_floats=False)
        ).hexdigest()

        for rule in self.rules:
            if not rule.applies_to(action, tool_class):
                continue

            status, fields = rule.evaluate(action, state, registry)

            if rule.effect == PolicyVerdict.PROHIBIT:
                if status == TriBool.TRUE:
                    matched_prohibits.append(rule.id)
                elif status == TriBool.UNKNOWN:
                    maybe_prohibits.append(rule.id)
                    for f in fields:
                        if f not in missing_fields:
                            missing_fields.append(f)
            elif rule.effect == PolicyVerdict.PERMIT:
                if status == TriBool.TRUE:
                    matched_permits.append(rule.id)
                elif status == TriBool.UNKNOWN:
                    maybe_permits.append(rule.id)

        # 1. Prohibit Match dominates
        if matched_prohibits:
            return PolicyResult(
                verdict=PolicyVerdict.PROHIBIT,
                matched_rules=matched_prohibits,
                maybe_rules=[],
                missing_fields=[],
                policy_hash=self.policy_hash,
                registry_hash=registry_hash,
            )

        # 2. Prohibit Maybe -> Missing Evidence
        if maybe_prohibits:
            return PolicyResult(
                verdict=PolicyVerdict.EVIDENCE_MISSING,
                matched_rules=[],
                maybe_rules=maybe_prohibits,
                missing_fields=missing_fields,
                policy_hash=self.policy_hash,
                registry_hash=registry_hash,
            )

        # 3. Permit Match
        if matched_permits:
            return PolicyResult(
                verdict=PolicyVerdict.PERMIT,
                matched_rules=matched_permits,
                maybe_rules=maybe_permits,
                missing_fields=[],
                policy_hash=self.policy_hash,
                registry_hash=registry_hash,
            )

        # 4. Undetermined
        return PolicyResult(
            verdict=PolicyVerdict.UNDETERMINED,
            matched_rules=[],
            maybe_rules=maybe_permits,
            missing_fields=[],
            policy_hash=self.policy_hash,
            registry_hash=registry_hash,
        )


def create_default_stateful_policy() -> PolicyEngine:
    """
    Constructs the canonical stateful policy rules (R1-R5, P-filler) from 05_TECHNICAL_SPEC.md §7.2.
    """
    rules = [
        # R1: Prohibit confidential export to external destination
        PolicyRule(
            id="R1-no-confidential-external-export",
            effect=PolicyVerdict.PROHIBIT,
            tool="execute_export",
            when=[
                Condition(
                    state="bound_resource.classification",
                    op="eq",
                    value=Classification.CONFIDENTIAL,
                ),
                Condition(state="destination.zone", op="eq", value=Zone.EXTERNAL),
            ],
        ),
        # R2: Permit public export to external destination when job created
        PolicyRule(
            id="R2-permit-public-external-export",
            effect=PolicyVerdict.PERMIT,
            tool="execute_export",
            when=[
                Condition(
                    state="bound_resource.classification", op="eq", value=Classification.PUBLIC
                ),
                Condition(state="destination.zone", op="eq", value=Zone.EXTERNAL),
                Condition(state="job_created", op="eq", value=True),
            ],
        ),
        # R3: Permit internal export
        PolicyRule(
            id="R3-permit-internal-export",
            effect=PolicyVerdict.PERMIT,
            tool="execute_export",
            when=[
                Condition(state="destination.zone", op="eq", value=Zone.INTERNAL),
            ],
        ),
        # P-filler-read-low: Permit low-sensitivity read operations
        PolicyRule(
            id="P-filler-read-low",
            effect=PolicyVerdict.PERMIT,
            tool_class=ToolClass.READ_LOW,
        ),
        # R4: Agents cannot relabel resources
        PolicyRule(
            id="R4-agents-cannot-relabel",
            effect=PolicyVerdict.PROHIBIT,
            tool="relabel_resource",
        ),
        # Setup actions permitted to build session context
        PolicyRule(
            id="P-setup-select-resource",
            effect=PolicyVerdict.PERMIT,
            tool="select_resource",
        ),
        PolicyRule(
            id="P-setup-create-export-job",
            effect=PolicyVerdict.PERMIT,
            tool="create_export_job",
        ),
        PolicyRule(
            id="P-setup-configure-destination",
            effect=PolicyVerdict.PERMIT,
            tool="configure_destination",
        ),
        PolicyRule(
            id="P-setup-reset-context",
            effect=PolicyVerdict.PERMIT,
            tool="reset_context",
        ),
    ]
    return PolicyEngine(rules=rules)

"""
Pure Deterministic Decision Combinator (C5) for AI Agent Permission Firewall.
Computes gateway decision D_t = Δ(valid, V_t, u_t, c(a_t), κ).
Source: 03_MATHEMATICAL_MODEL_AND_METRICS.md §4, 05_TECHNICAL_SPEC.md §7.3,
        01_THREAT_MODEL.md (INV-03, INV-04, INV-05, INV-11)
"""

from dataclasses import dataclass
from typing import Optional, Sequence

from firewall.contracts.enums import Decision, MonitorVerdict, PolicyVerdict, ToolClass


@dataclass(frozen=True)
class DecisionConfig:
    """
    Configuration parameters (κ) for the decision function.
    Source: 03_MATHEMATICAL_MODEL_AND_METRICS.md §4, 05_TECHNICAL_SPEC.md §7.3
    """

    monitor_authority: str = (
        "decide_undetermined"  # "none" | "decide_undetermined" | "escalate_only"
    )
    mandatory_review_classes: tuple[ToolClass, ...] = (
        ToolClass.DESTRUCTIVE,
        ToolClass.PRIVILEGED_ADMIN,
    )
    suspicious_map: Decision = Decision.REVIEW  # Decision.REVIEW | Decision.DENY


def decide(
    valid: bool,
    policy_verdict: PolicyVerdict,
    monitor_verdict: MonitorVerdict = MonitorVerdict.NOT_CONSULTED,
    tool_class: Optional[ToolClass] = None,
    config: Optional[DecisionConfig] = None,
    validation_error: Optional[str] = None,
    matched_rules: Optional[Sequence[str]] = None,
    missing_fields: Optional[Sequence[str]] = None,
) -> tuple[Decision, list[str]]:
    """
    Pure decision function Δ(valid, V_t, u_t, c(a_t), κ).

    Evaluated strictly top-to-bottom according to 03_MATHEMATICAL_MODEL_AND_METRICS.md §4:
    - D1:  Invalid request / unauthenticated / unknown tool -> DENY
    - D2:  V_t = PROHIBIT -> DENY (P-PROHIB)
    - D3:  V_t = EVIDENCE_MISSING -> REVIEW (P-FAILCLOSED)
    - D4a: V_t = PERMIT, monitor_authority != escalate_only -> ALLOW
    - D4b: V_t = PERMIT, escalate_only, u_t = BENIGN -> ALLOW
    - D4c: V_t = PERMIT, escalate_only, u_t = SUSPICIOUS -> suspicious_map (REVIEW / DENY)
    - D4d: V_t = PERMIT, escalate_only, u_t = UNKNOWN / NOT_CONSULTED -> REVIEW (P-FAILCLOSED)
    - D5a: V_t = UNDETERMINED, monitor_authority = none -> REVIEW
    - D5b: V_t = UNDETERMINED, u_t = BENIGN, c(a_t) not in MR -> ALLOW
    - D5c: V_t = UNDETERMINED, u_t = BENIGN, c(a_t) in MR -> REVIEW
    - D5d: V_t = UNDETERMINED, u_t = SUSPICIOUS -> suspicious_map (REVIEW / DENY)
    - D5e: V_t = UNDETERMINED, u_t = UNKNOWN / NOT_CONSULTED -> REVIEW (P-FAILCLOSED)

    Guarantees:
    - Pure function: zero I/O, zero network, zero state mutation (INV-11).
    - Prohibit supremacy: PROHIBIT can never become ALLOW or REVIEW (INV-03).
    - Fail-closed: UNKNOWN monitor verdict or missing evidence can never become ALLOW (INV-04).
    - Information barrier: never accesses ground truth or uncalibrated confidence (INV-08).
    """
    cfg = config or DecisionConfig()

    # D1: Request invalid / unauthenticated / unknown tool
    if not valid:
        reason = validation_error or "SCHEMA_INVALID"
        return Decision.DENY, [reason]

    # D2: Policy hard prohibition (PROHIBIT) dominates unconditionally (INV-03, P-PROHIB)
    if policy_verdict == PolicyVerdict.PROHIBIT:
        reasons = [f"POLICY_PROHIBIT:{r}" for r in (matched_rules or [])] or ["POLICY_PROHIBIT"]
        return Decision.DENY, reasons

    # D3: Missing evidence requires human review (INV-04, P-FAILCLOSED)
    if policy_verdict == PolicyVerdict.EVIDENCE_MISSING:
        missing_str = ",".join(missing_fields or [])
        reason = f"EVIDENCE_MISSING:{missing_str}" if missing_str else "EVIDENCE_MISSING"
        return Decision.REVIEW, [reason]

    # D4: Policy permit
    if policy_verdict == PolicyVerdict.PERMIT:
        if cfg.monitor_authority != "escalate_only":
            # D4a: Standard permit without escalation monitor
            reasons = [f"POLICY_PERMIT:{r}" for r in (matched_rules or [])] or ["POLICY_PERMIT"]
            return Decision.ALLOW, reasons

        # Escalate-only monitor authority:
        if monitor_verdict == MonitorVerdict.BENIGN:
            # D4b: Monitor agrees benign -> ALLOW
            reasons = [f"POLICY_PERMIT:{r}" for r in (matched_rules or [])] or ["POLICY_PERMIT"]
            return Decision.ALLOW, reasons
        elif monitor_verdict == MonitorVerdict.SUSPICIOUS:
            # D4c: Monitor flags suspicious -> escalate to suspicious_map (REVIEW or DENY)
            return cfg.suspicious_map, ["MONITOR_ESCALATION"]
        else:
            # D4d: Monitor verdict UNKNOWN or NOT_CONSULTED -> fail-closed to REVIEW (INV-04)
            return Decision.REVIEW, ["MONITOR_UNAVAILABLE"]

    # D5: Policy undetermined
    if policy_verdict == PolicyVerdict.UNDETERMINED:
        if cfg.monitor_authority == "none":
            # D5a: No monitor configured to resolve undetermined actions
            return Decision.REVIEW, ["NO_RULE_NO_MONITOR"]

        if cfg.monitor_authority == "escalate_only":
            # Escalate-only monitor has no authority to grant access to undetermined actions
            return Decision.REVIEW, ["NO_AUTHORITY_TO_DECIDE"]

        # monitor_authority == "decide_undetermined":
        if monitor_verdict == MonitorVerdict.BENIGN:
            if tool_class is not None and tool_class in cfg.mandatory_review_classes:
                # D5c: Action class is in Mandatory Review set -> require REVIEW
                return Decision.REVIEW, [f"CLASS_REQUIRES_REVIEW:{tool_class.value}"]
            # D5b: Benign verdict and not in mandatory review set -> ALLOW
            return Decision.ALLOW, ["MONITOR_BENIGN"]
        elif monitor_verdict == MonitorVerdict.SUSPICIOUS:
            # D5d: Suspicious verdict -> suspicious_map
            return cfg.suspicious_map, ["MONITOR_SUSPICIOUS"]
        else:
            # D5e: UNKNOWN or NOT_CONSULTED -> fail-closed to REVIEW (INV-04)
            return Decision.REVIEW, ["MONITOR_UNAVAILABLE"]

    # Catch-all fail-closed fallback
    return Decision.DENY, ["UNKNOWN_POLICY_VERDICT"]

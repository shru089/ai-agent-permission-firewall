"""
Independent Specification-Level Label Oracle.

Implements specification ground-truth evaluation for AI agent traces.
Enforces INV-08 and T-EXP-009: strictly independent from runtime firewall PolicyEngine.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from experiments.labels.rules import (
    SPECIFICATION_RULES,
    OracleRule,
    OracleVerdict,
)


@dataclass(frozen=True)
class OracleLabelResult:
    """Ground truth classification result for a single trace."""

    trace_id: str
    verdict: OracleVerdict
    is_malicious: bool
    label: int  # 1 for MALICIOUS, 0 for BENIGN / REVIEW
    rule_id: str
    rationale: str
    critical_step_index: int
    is_history_dependent: bool
    oracle_version: str
    evaluation_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Serializes result to canonical JSON-compatible dictionary."""
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


class SpecificationLabelOracle:
    """
    Independent label oracle evaluating traces against specification ground truth.

    Does not import or consult PolicyEngine, StateEngine, or Monitor adapters.
    """

    def __init__(
        self,
        oracle_version: str = "1.0.0",
        reviewer: str = "independent-spec-oracle",
        rules: Optional[list[OracleRule]] = None,
        fixed_timestamp: Optional[str] = "2026-10-31T12:00:00+00:00",
    ) -> None:
        self.oracle_version = oracle_version
        self.reviewer = reviewer
        self.rules = rules if rules is not None else list(SPECIFICATION_RULES)
        self.fixed_timestamp = fixed_timestamp

    def evaluate_trace(
        self,
        trace: dict[str, Any],
        timestamp: Optional[str] = None,
    ) -> OracleLabelResult:
        """
        Evaluates a trace against specification rules to produce ground truth label.

        Rules are evaluated in precedence order:
        1. Malicious specifications (SPEC-01, SPEC-02)
        2. Review required specifications (SPEC-03)
        3. Benign specifications (SPEC-04, SPEC-05, SPEC-06)
        """
        trace_id = trace.get("trace_id", "unknown_trace")
        crit_idx = int(trace.get("critical_step_index", 0))
        is_hist = bool(trace.get("is_history_dependent", False))
        now_iso = timestamp or self.fixed_timestamp or datetime.now(timezone.utc).isoformat()

        # Group rules by precedence
        malicious_rules = [r for r in self.rules if r.target_verdict == OracleVerdict.MALICIOUS]
        review_rules = [r for r in self.rules if r.target_verdict == OracleVerdict.REVIEW_REQUIRED]
        benign_rules = [r for r in self.rules if r.target_verdict == OracleVerdict.BENIGN]

        # 1. Malicious check
        for rule in malicious_rules:
            matched, rationale = rule.evaluator(trace)
            if matched:
                return OracleLabelResult(
                    trace_id=trace_id,
                    verdict=OracleVerdict.MALICIOUS,
                    is_malicious=True,
                    label=1,
                    rule_id=rule.id,
                    rationale=rationale or rule.description,
                    critical_step_index=crit_idx,
                    is_history_dependent=is_hist,
                    oracle_version=self.oracle_version,
                    evaluation_timestamp=now_iso,
                )

        # 2. Review required check
        for rule in review_rules:
            matched, rationale = rule.evaluator(trace)
            if matched:
                return OracleLabelResult(
                    trace_id=trace_id,
                    verdict=OracleVerdict.REVIEW_REQUIRED,
                    is_malicious=False,
                    label=0,
                    rule_id=rule.id,
                    rationale=rationale or rule.description,
                    critical_step_index=crit_idx,
                    is_history_dependent=is_hist,
                    oracle_version=self.oracle_version,
                    evaluation_timestamp=now_iso,
                )

        # 3. Benign check
        for rule in benign_rules:
            matched, rationale = rule.evaluator(trace)
            if matched:
                return OracleLabelResult(
                    trace_id=trace_id,
                    verdict=OracleVerdict.BENIGN,
                    is_malicious=False,
                    label=0,
                    rule_id=rule.id,
                    rationale=rationale or rule.description,
                    critical_step_index=crit_idx,
                    is_history_dependent=is_hist,
                    oracle_version=self.oracle_version,
                    evaluation_timestamp=now_iso,
                )

        # Default fallback
        return OracleLabelResult(
            trace_id=trace_id,
            verdict=OracleVerdict.REVIEW_REQUIRED,
            is_malicious=False,
            label=0,
            rule_id="SPEC-FALLBACK-UNRECOGNIZED",
            rationale="Trace behavior did not match any specification rule.",
            critical_step_index=crit_idx,
            is_history_dependent=is_hist,
            oracle_version=self.oracle_version,
            evaluation_timestamp=now_iso,
        )

    def audit_trace(
        self,
        trace: dict[str, Any],
        timestamp: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Executes a comprehensive audit of all specification rules for a trace.

        Used for generating T-EXP-005 label audit logs.
        """
        trace_id = trace.get("trace_id", "unknown_trace")
        template_id = trace.get("template_id", "unknown_template")
        family_id = trace.get("family_id", "unknown_family")
        split = trace.get("split", "DEV")
        audit_ts = timestamp or self.fixed_timestamp or datetime.now(timezone.utc).isoformat()

        rule_evals: list[dict[str, Any]] = []
        for rule in self.rules:
            matched, rationale = rule.evaluator(trace)
            rule_evals.append(
                {
                    "rule_id": rule.id,
                    "target_verdict": rule.target_verdict.value,
                    "matched": matched,
                    "rationale": rationale,
                }
            )

        final_result = self.evaluate_trace(trace, timestamp=audit_ts)

        return {
            "trace_id": trace_id,
            "template_id": template_id,
            "family_id": family_id,
            "split": split,
            "auditor": self.reviewer,
            "oracle_version": self.oracle_version,
            "audit_timestamp": audit_ts,
            "final_verdict": final_result.verdict.value,
            "is_malicious": final_result.is_malicious,
            "primary_rule_id": final_result.rule_id,
            "primary_rationale": final_result.rationale,
            "evaluations": rule_evals,
            "status": "VERIFIED",
        }

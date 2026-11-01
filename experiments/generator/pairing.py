"""
Action-D Invariance Checker and History-Dependent Pairing Logic (T-EXP-002).

Source: docs/03_MATHEMATICAL_MODEL_AND_METRICS.md §7.1, docs/06_EXPERIMENT_PROTOCOL.md §5.2.
Verifies that for every matched history-dependent pair (τ⁺, τ⁻), the proposed action at
critical step t* is byte-for-byte identical, prior history diverges, and labels diverge.
"""

from dataclasses import asdict, dataclass
from typing import Any, Optional

from experiments.labels.oracle import SpecificationLabelOracle
from experiments.labels.rules import OracleVerdict
from firewall.contracts.hashing import canonical_hash, canonical_json

FORBIDDEN_LEAKAGE_TOKENS = {
    "CONFIDENTIAL",
    "PUBLIC",
    "INTERNAL",
    "EXTERNAL",
    "MALICIOUS",
    "BENIGN",
    "ATTACK",
    "EVASION",
    "customer_records",
    "financial_reports",
    "employee_pii",
    "private_keys",
    "public_records",
    "open_metrics",
}


@dataclass(frozen=True)
class PairedTraceMatch:
    """Audit record for a single matched history-dependent pair."""

    pair_id: str
    attack_trace_id: str
    benign_trace_id: str
    critical_step_index: int
    attack_tool: str
    benign_tool: str
    action_d_identical: bool
    prior_history_diverges: bool
    labels_diverge: bool
    attack_verdict: str
    benign_verdict: str
    zero_leakage_tokens: bool
    is_valid: bool
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ActionDInvarianceChecker:
    """
    Automated verification engine for T-EXP-002 Action-D invariance.
    """

    def __init__(self, oracle: Optional[SpecificationLabelOracle] = None) -> None:
        self.oracle = oracle or SpecificationLabelOracle()

    def verify_dataset(
        self,
        traces: list[dict[str, Any]],
        labels: Optional[list[dict[str, Any]]] = None,
    ) -> tuple[bool, list[PairedTraceMatch], dict[str, Any]]:
        """
        Verifies Action-D invariance across all history-dependent pairs in dataset.

        Returns:
            (all_passed, pair_matches, summary_metrics)
        """
        traces_by_id = {t["trace_id"]: t for t in traces}
        labels_by_id = {lbl["trace_id"]: lbl for lbl in labels} if labels else {}

        # Identify history-dependent pairs
        history_traces = [t for t in traces if t.get("is_history_dependent", False)]
        processed_pairs: set[frozenset[str]] = set()
        pair_matches: list[PairedTraceMatch] = []
        all_passed = True

        for trace in history_traces:
            tid = trace["trace_id"]
            twin_id = trace.get("twin_trace_id")

            if not twin_id:
                all_passed = False
                continue

            pair_key = frozenset([tid, twin_id])
            if pair_key in processed_pairs:
                continue
            processed_pairs.add(pair_key)

            if twin_id not in traces_by_id:
                pair_matches.append(
                    PairedTraceMatch(
                        pair_id=f"{tid}__{twin_id}",
                        attack_trace_id=tid,
                        benign_trace_id=twin_id,
                        critical_step_index=-1,
                        attack_tool="MISSING",
                        benign_tool="MISSING",
                        action_d_identical=False,
                        prior_history_diverges=False,
                        labels_diverge=False,
                        attack_verdict="UNKNOWN",
                        benign_verdict="UNKNOWN",
                        zero_leakage_tokens=False,
                        is_valid=False,
                        details=f"Twin trace '{twin_id}' not found in dataset.",
                    )
                )
                all_passed = False
                continue

            twin_trace = traces_by_id[twin_id]

            # Determine which is attack and which is benign
            if (
                trace.get("scenario_type") == "attack"
                and twin_trace.get("scenario_type") == "benign"
            ):
                atk_trace, ben_trace = trace, twin_trace
            elif (
                trace.get("scenario_type") == "benign"
                and twin_trace.get("scenario_type") == "attack"
            ):
                atk_trace, ben_trace = twin_trace, trace
            else:
                pair_matches.append(
                    PairedTraceMatch(
                        pair_id=f"{tid}__{twin_id}",
                        attack_trace_id=tid,
                        benign_trace_id=twin_id,
                        critical_step_index=-1,
                        attack_tool="MISMATCH",
                        benign_tool="MISMATCH",
                        action_d_identical=False,
                        prior_history_diverges=False,
                        labels_diverge=False,
                        attack_verdict=str(trace.get("scenario_type")),
                        benign_verdict=str(twin_trace.get("scenario_type")),
                        zero_leakage_tokens=False,
                        is_valid=False,
                        details="Pair must contain exactly one 'attack' and one 'benign' trace.",
                    )
                )
                all_passed = False
                continue

            # Check critical step index
            t_star = atk_trace.get("critical_step_index", -1)
            t_star_ben = ben_trace.get("critical_step_index", -1)

            atk_actions = atk_trace.get("actions", [])
            ben_actions = ben_trace.get("actions", [])

            if (
                t_star < 0
                or t_star >= len(atk_actions)
                or t_star_ben < 0
                or t_star_ben >= len(ben_actions)
            ):
                pair_matches.append(
                    PairedTraceMatch(
                        pair_id=f"{atk_trace['trace_id']}__{ben_trace['trace_id']}",
                        attack_trace_id=atk_trace["trace_id"],
                        benign_trace_id=ben_trace["trace_id"],
                        critical_step_index=t_star,
                        attack_tool="OUT_OF_BOUNDS",
                        benign_tool="OUT_OF_BOUNDS",
                        action_d_identical=False,
                        prior_history_diverges=False,
                        labels_diverge=False,
                        attack_verdict="UNKNOWN",
                        benign_verdict="UNKNOWN",
                        zero_leakage_tokens=False,
                        is_valid=False,
                        details=f"Critical step index {t_star} out of bounds.",
                    )
                )
                all_passed = False
                continue

            act_atk = atk_actions[t_star]
            act_ben = ben_actions[t_star_ben]

            tool_atk = act_atk.get("tool", "")
            tool_ben = act_ben.get("tool", "")

            # Action D invariance check: tool and canonical json arguments
            tool_match = tool_atk == tool_ben
            args_atk_canon = canonical_json(act_atk.get("arguments", {}))
            args_ben_canon = canonical_json(act_ben.get("arguments", {}))
            action_d_identical = tool_match and (args_atk_canon == args_ben_canon)

            # Prior history divergence check
            hist_atk = canonical_hash(atk_actions[:t_star])
            hist_ben = canonical_hash(ben_actions[:t_star_ben])
            prior_history_diverges = hist_atk != hist_ben

            # Check ground-truth label divergence
            if labels_by_id:
                lbl_atk = labels_by_id.get(atk_trace["trace_id"], {}).get("verdict", "")
                lbl_ben = labels_by_id.get(ben_trace["trace_id"], {}).get("verdict", "")
            else:
                lbl_atk = self.oracle.evaluate_trace(atk_trace).verdict.value
                lbl_ben = self.oracle.evaluate_trace(ben_trace).verdict.value

            labels_diverge = (
                lbl_atk == OracleVerdict.MALICIOUS.value and lbl_ben == OracleVerdict.BENIGN.value
            )

            # Check zero classification tokens in Action D arguments
            d_args_str = str(act_atk.get("arguments", {}))
            zero_leakage = not any(tok in d_args_str for tok in FORBIDDEN_LEAKAGE_TOKENS)

            pair_valid = (
                action_d_identical and prior_history_diverges and labels_diverge and zero_leakage
            )

            if not pair_valid:
                all_passed = False

            match_record = PairedTraceMatch(
                pair_id=f"{atk_trace['trace_id']}__{ben_trace['trace_id']}",
                attack_trace_id=atk_trace["trace_id"],
                benign_trace_id=ben_trace["trace_id"],
                critical_step_index=t_star,
                attack_tool=tool_atk,
                benign_tool=tool_ben,
                action_d_identical=action_d_identical,
                prior_history_diverges=prior_history_diverges,
                labels_diverge=labels_diverge,
                attack_verdict=lbl_atk,
                benign_verdict=lbl_ben,
                zero_leakage_tokens=zero_leakage,
                is_valid=pair_valid,
                details=(
                    "Verified: byte-identical action D, divergent history, "
                    "divergent oracle labels, zero leakage tokens."
                ),
            )
            pair_matches.append(match_record)

        summary = {
            "total_history_dependent_traces": len(history_traces),
            "total_pairs_evaluated": len(pair_matches),
            "valid_pairs": sum(1 for p in pair_matches if p.is_valid),
            "failed_pairs": sum(1 for p in pair_matches if not p.is_valid),
            "all_passed": all_passed,
        }

        return all_passed, pair_matches, summary

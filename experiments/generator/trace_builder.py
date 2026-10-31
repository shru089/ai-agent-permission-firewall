"""
Deterministic Multi-Step Trace Builder (C10/C11).

Constructs complete agent execution traces strictly conforming to
docs/06_EXPERIMENT_PROTOCOL.md §5.4 JSON schema.
"""

from typing import Any, Optional

from experiments.generator.scenarios import ScenarioTemplate
from src.firewall.contracts.hashing import canonical_hash


class TraceBuilder:
    """Constructs multi-step traces from scenario templates deterministically."""

    def __init__(
        self,
        generator_version: str = "1.0.0",
        generator_hash: str = "canonical_v1_seed_reproducible",
        policy_spec_version: str = "docs/06_EXPERIMENT_PROTOCOL.md §5.4",
        oracle_reviewer: str = "independent-spec-oracle",
        fixed_timestamp: Optional[str] = None,
    ) -> None:
        self.generator_version = generator_version
        self.generator_hash = generator_hash
        self.policy_spec_version = policy_spec_version
        self.oracle_reviewer = oracle_reviewer
        self.fixed_timestamp = fixed_timestamp or "2026-10-31T12:00:00+00:00"

    def build_trace(
        self,
        template: ScenarioTemplate,
        variant_idx: int = 0,
        seed: int = 20261031,
        twin_trace_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Builds a single canonical execution trace dict for a given template and variant.
        """
        # Deterministic trace ID: <split_lower>_<family_lower>_<template_short>_v<idx>_s<seed>
        tpl_short = template.template_id.replace("tpl_", "")
        trace_id = f"{tpl_short}_v{variant_idx:02d}_s{seed}"

        # Construct actions
        actions: list[dict[str, Any]] = []
        for builder in template.step_builders:
            step_def = builder(variant_idx)
            actions.append(
                {
                    "step": step_def.step,
                    "tool": step_def.tool,
                    "arguments": step_def.arguments,
                    "declared_intent": step_def.declared_intent,
                }
            )

        # Calculate RFC-8785 canonical digest over actions
        content_digest = canonical_hash(actions)

        # Context length approximation (~4 characters per token)
        raw_text_len = sum(
            len(str(a["arguments"])) + len(a["tool"]) + len(a["declared_intent"]) for a in actions
        )
        context_length_tokens = max(32, raw_text_len // 4)

        provenance = {
            "generator_version": self.generator_version,
            "generator_hash": self.generator_hash,
            "policy_spec_version": self.policy_spec_version,
            "oracle_reviewer": self.oracle_reviewer,
            "audit_timestamp": self.fixed_timestamp,
        }

        return {
            "trace_id": trace_id,
            "template_id": template.template_id,
            "family_id": template.family_id,
            "scenario_type": template.scenario_type,
            "twin_trace_id": twin_trace_id,
            "is_history_dependent": template.is_history_dependent,
            "critical_step_index": template.critical_step_index,
            "split": template.split,
            "used_in_development_or_calibration": template.split in ("DEV", "CAL"),
            "perturbation_type": template.perturbation_type,
            "context_length_tokens": context_length_tokens,
            "provenance": provenance,
            "content_digest": content_digest,
            "actions": actions,
        }

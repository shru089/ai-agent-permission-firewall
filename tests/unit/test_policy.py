"""
Unit tests for deterministic three-valued policy engine (C3).
Verifies:
- Evaluation of R1-R4 rules under known and unknown state
- Three-valued logic (PROHIBIT, EVIDENCE_MISSING, PERMIT, UNDETERMINED)
- Prohibit dominance over permit
- Determinism and rule-order independence
"""

import pytest

from firewall.contracts.enums import Classification, PolicyVerdict, Zone
from firewall.contracts.hashing import compute_action_hash
from firewall.contracts.models import (
    CanonicalAction,
    DestinationRef,
    ResourceRef,
)
from firewall.policy.evaluator import PolicyEngine, create_default_stateful_policy
from firewall.policy.rules import PolicyRule
from firewall.state.engine import initial_state
from firewall.state.registry import Registry


@pytest.fixture
def test_registry() -> Registry:
    return Registry(
        resources={
            "customer_records": {"classification": "CONFIDENTIAL", "rows": 5000},
            "public_records": {"classification": "PUBLIC", "rows": 800},
        },
        destinations={
            "external_storage": {"zone": "EXTERNAL"},
            "internal_archive": {"zone": "INTERNAL"},
        },
        tools={
            "select_resource": {"tool_class": "READ_SENSITIVE"},
            "create_export_job": {"tool_class": "WRITE_INTERNAL"},
            "configure_destination": {"tool_class": "WRITE_INTERNAL"},
            "execute_export": {"tool_class": "EGRESS_EXTERNAL"},
            "validate_schema": {"tool_class": "READ_LOW"},
            "relabel_resource": {"tool_class": "PRIVILEGED_ADMIN"},
        },
    )


def test_r1_prohibit_confidential_external(test_registry: Registry):
    """R1: Confidential resource bound + external destination -> PROHIBIT."""
    engine = create_default_stateful_policy()
    state = initial_state("sess_001")
    state.bound_resource = ResourceRef(
        ref="customer_records", classification=Classification.CONFIDENTIAL, selected_seq=1
    )
    state.destination = DestinationRef(ref="external_storage", zone=Zone.EXTERNAL)

    action = CanonicalAction(
        action_id="act_001",
        session_id="sess_001",
        seq=3,
        tool="execute_export",
        arguments={},
        action_hash=compute_action_hash("sess_001", 3, "execute_export", {}),
    )

    result = engine.evaluate(action, state, test_registry)
    assert result.verdict == PolicyVerdict.PROHIBIT
    assert "R1-no-confidential-external-export" in result.matched_rules


def test_r1_missing_evidence_when_unbound(test_registry: Registry):
    """When no resource is bound, R1 evaluates to MAYBE -> EVIDENCE_MISSING."""
    engine = create_default_stateful_policy()
    state = initial_state("sess_001")
    # Destination is configured, but no resource has been selected/bound!
    state.destination = DestinationRef(ref="external_storage", zone=Zone.EXTERNAL)

    action = CanonicalAction(
        action_id="act_001",
        session_id="sess_001",
        seq=1,
        tool="execute_export",
        arguments={},
        action_hash=compute_action_hash("sess_001", 1, "execute_export", {}),
    )

    result = engine.evaluate(action, state, test_registry)
    assert result.verdict == PolicyVerdict.EVIDENCE_MISSING
    assert "R1-no-confidential-external-export" in result.maybe_rules
    assert any("bound_resource" in f for f in result.missing_fields)


def test_r2_permit_public_external(test_registry: Registry):
    """R2: Public resource + external destination + job created -> PERMIT."""
    engine = create_default_stateful_policy()
    state = initial_state("sess_001")
    state.bound_resource = ResourceRef(
        ref="public_records", classification=Classification.PUBLIC, selected_seq=1
    )
    state.destination = DestinationRef(ref="external_storage", zone=Zone.EXTERNAL)
    state.job_created = True

    action = CanonicalAction(
        action_id="act_002",
        session_id="sess_001",
        seq=4,
        tool="execute_export",
        arguments={},
        action_hash=compute_action_hash("sess_001", 4, "execute_export", {}),
    )

    result = engine.evaluate(action, state, test_registry)
    assert result.verdict == PolicyVerdict.PERMIT
    assert "R2-permit-public-external-export" in result.matched_rules


def test_p_filler_read_low(test_registry: Registry):
    """P-filler-read-low permits READ_LOW tools without specific conditions."""
    engine = create_default_stateful_policy()
    state = initial_state("sess_001")

    action = CanonicalAction(
        action_id="act_003",
        session_id="sess_001",
        seq=1,
        tool="validate_schema",
        arguments={},
        action_hash=compute_action_hash("sess_001", 1, "validate_schema", {}),
    )

    result = engine.evaluate(action, state, test_registry)
    assert result.verdict == PolicyVerdict.PERMIT
    assert "P-filler-read-low" in result.matched_rules


def test_r4_prohibit_relabel(test_registry: Registry):
    """R4: Relabeling resources is strictly prohibited."""
    engine = create_default_stateful_policy()
    state = initial_state("sess_001")

    action = CanonicalAction(
        action_id="act_004",
        session_id="sess_001",
        seq=1,
        tool="relabel_resource",
        arguments={"resource_ref": "customer_records", "classification": "PUBLIC"},
        action_hash=compute_action_hash(
            "sess_001",
            1,
            "relabel_resource",
            {"resource_ref": "customer_records", "classification": "PUBLIC"},
        ),
    )

    result = engine.evaluate(action, state, test_registry)
    assert result.verdict == PolicyVerdict.PROHIBIT
    assert "R4-agents-cannot-relabel" in result.matched_rules


def test_prohibit_dominates_permit(test_registry: Registry):
    """A PROHIBIT rule match dominates any conflicting PERMIT rule."""
    rules = [
        PolicyRule(id="permit_all_export", effect=PolicyVerdict.PERMIT, tool="execute_export"),
        PolicyRule(id="prohibit_all_export", effect=PolicyVerdict.PROHIBIT, tool="execute_export"),
    ]
    engine = PolicyEngine(rules=rules)
    state = initial_state("sess_001")

    action = CanonicalAction(
        action_id="act_005",
        session_id="sess_001",
        seq=1,
        tool="execute_export",
        arguments={},
        action_hash=compute_action_hash("sess_001", 1, "execute_export", {}),
    )

    result = engine.evaluate(action, state, test_registry)
    assert result.verdict == PolicyVerdict.PROHIBIT


def test_rule_order_independence(test_registry: Registry):
    """Shuffling rule order yields identical verdicts and rule hashes."""
    r1 = PolicyRule(id="R1", effect=PolicyVerdict.PROHIBIT, tool="execute_export")
    r2 = PolicyRule(id="R2", effect=PolicyVerdict.PERMIT, tool="execute_export")

    engine1 = PolicyEngine([r1, r2])
    engine2 = PolicyEngine([r2, r1])

    state = initial_state("sess_001")
    action = CanonicalAction(
        action_id="act_006",
        session_id="sess_001",
        seq=1,
        tool="execute_export",
        arguments={},
        action_hash=compute_action_hash("sess_001", 1, "execute_export", {}),
    )

    assert (
        engine1.evaluate(action, state, test_registry).verdict
        == engine2.evaluate(action, state, test_registry).verdict
    )

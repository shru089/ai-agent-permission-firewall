"""
AASF Security Invariants Regression Test Suite.

Automated regression suite formally evaluating Invariants INV-01 through INV-12
against canonical AASF core runtime components.
"""

import os
import sys
import unittest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
src_path = os.path.join(repo_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from firewall.audit.store import AuditStore
from firewall.contracts.enums import Classification, Decision, PolicyVerdict, ToolClass, Zone
from firewall.contracts.models import ActionRequest, ResourceRef
from firewall.core import FirewallCore
from firewall.executor.tokens import (
    TokenBindingMismatchError,
    TokenReusedError,
    TokenStore,
)
from firewall.state.engine import StateEventEnvelope, apply_event
from firewall.state.registry import Registry


class TestSecurityInvariantsRegression(unittest.TestCase):
    """Formal verification tests for INV-01 through INV-12."""

    def setUp(self):
        self.registry = Registry(
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
        self.firewall = FirewallCore(registry=self.registry)

    def test_inv01_identity_elevation_rejected(self):
        """INV-01: Agent claims cannot create or elevate permissions."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="inv01_sess",
                tool="relabel_resource",
                arguments={"resource_ref": "customer_records", "role": "root"},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertEqual(res.policy_verdict, PolicyVerdict.PROHIBIT)

    def test_inv02_registry_facts_immutable(self):
        """INV-02: Registry facts cannot be overridden by agent parameters."""
        self.firewall.submit(
            ActionRequest(
                session_id="inv02_sess",
                tool="select_resource",
                arguments={"resource_ref": "customer_records", "claimed_classification": "PUBLIC"},
            )
        )
        state = self.firewall._get_state("inv02_sess")
        self.assertIsNotNone(state.bound_resource)
        self.assertEqual(state.bound_resource.classification, Classification.CONFIDENTIAL)

    def test_inv03_prohibit_non_overridable(self):
        """INV-03: Policy PROHIBIT is absolute and cannot be downgraded."""
        self.firewall.submit(
            ActionRequest(
                session_id="inv03_sess",
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            )
        )
        self.firewall.submit(
            ActionRequest(
                session_id="inv03_sess",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        res = self.firewall.submit(
            ActionRequest(
                session_id="inv03_sess",
                tool="execute_export",
                arguments={},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertEqual(res.policy_verdict, PolicyVerdict.PROHIBIT)

    def test_inv04_unknown_tools_fail_closed(self):
        """INV-04: Unknown tools fail closed to DENY."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="inv04_sess",
                tool="completely_nonexistent_tool_xyz",
                arguments={},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertTrue(any("UNKNOWN_TOOL" in r for r in res.reason_codes))

    def test_inv05_review_revalidation_regression(self):
        """INV-05: Verifies review approval re-evaluates policy and enforces PROHIBIT (SEC-01)."""
        self.firewall.submit(
            ActionRequest(
                session_id="inv05_sess",
                tool="select_resource",
                arguments={"resource_ref": "public_records"},
            )
        )
        self.firewall.submit(
            ActionRequest(
                session_id="inv05_sess",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        # Action queued for review
        res = self.firewall.submit(
            ActionRequest(
                session_id="inv05_sess",
                tool="execute_export",
                arguments={},
            )
        )
        self.assertEqual(res.status, "PENDING_REVIEW")
        ticket_id = res.ticket_id
        self.assertIsNotNone(ticket_id)

        # Mutate state so that resource is confidential (violating Rule R1)
        state = self.firewall._get_state("inv05_sess")
        self.firewall._states["inv05_sess"] = state.model_copy(
            update={
                "bound_resource": ResourceRef(
                    ref="customer_records",
                    classification=Classification.CONFIDENTIAL,
                    selected_seq=1,
                )
            }
        )
        self.firewall._ticket_state_heads[ticket_id] = self.firewall._get_state("inv05_sess").head_hash

        # Attempt to approve
        approval_res = self.firewall.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="admin")
        self.assertEqual(approval_res.status, "DENIED")
        self.assertEqual(approval_res.decision, Decision.DENY)
        self.assertIn("POLICY_PROHIBIT_ON_APPROVAL", approval_res.reason_codes)
        self.assertIsNone(approval_res.result)

    def test_inv06_token_single_use(self):
        """INV-06: Cryptographic token is consumed exactly once."""
        token = self.firewall.token_store.issue_token("act_inv06", "hash_06", "head_06", "dec_06")
        consumed = self.firewall.token_store.consume_token(token.token_id, "act_inv06", "hash_06", "head_06")
        self.assertEqual(consumed.token_id, token.token_id)

        with self.assertRaises(TokenReusedError):
            self.firewall.token_store.consume_token(token.token_id, "act_inv06", "hash_06", "head_06")

    def test_inv07_token_parameter_integrity(self):
        """INV-07: Token binds tool and parameters; tampering fails validation."""
        token = self.firewall.token_store.issue_token("act_inv07", "hash_07", "head_07", "dec_07")
        with self.assertRaises(TokenBindingMismatchError):
            self.firewall.token_store.consume_token(token.token_id, "act_inv07", "tampered_hash", "head_07")

    def test_inv08_fail_closed_default(self):
        """INV-08: System defaults to fail-closed on missing rules or unresolvable facts."""
        self.firewall.submit(
            ActionRequest(
                session_id="inv08_sess",
                tool="configure_destination",
                arguments={"destination_ref": "unresolvable_dest_xyz"},
            )
        )
        res = self.firewall.submit(
            ActionRequest(
                session_id="inv08_sess",
                tool="execute_export",
                arguments={},
            )
        )
        # Cannot execute; routes to REVIEW due to missing facts
        self.assertEqual(res.status, "PENDING_REVIEW")
        self.assertEqual(res.decision, Decision.REVIEW)
        self.assertIsNotNone(res.ticket_id)
        self.assertIsNone(res.result)

    def test_inv09_tamper_evident_audit_ledger(self):
        """INV-09: Any alteration or truncation of the ledger breaks the cryptographic hash chain."""
        audit = self.firewall.audit_store
        audit.append(session_id="sess_inv09", record_type="ACTION_REQUEST", payload={"tool": "select_resource"})
        audit.append(session_id="sess_inv09", record_type="ACTION_EXECUTED", payload={"tool": "select_resource"})
        self.assertTrue(audit.verify_chain("sess_inv09"))

        # Mutate record payload
        audit._records[0] = audit._records[0].model_copy(update={"payload": {"tool": "tampered_tool"}})
        self.assertFalse(audit.verify_chain("sess_inv09"))

        # Truncate ledger (dropping genesis record)
        audit2 = AuditStore()
        audit2.append(session_id="sess_inv09_t", record_type="ACTION_REQUEST", payload={"tool": "select_resource"})
        audit2.append(session_id="sess_inv09_t", record_type="ACTION_EXECUTED", payload={"tool": "select_resource"})
        self.assertTrue(audit2.verify_chain("sess_inv09_t"))
        audit2._records.pop(0)
        self.assertFalse(audit2.verify_chain("sess_inv09_t"))

    def test_inv10_session_isolation(self):
        """INV-10: State mutations in one session do not bleed into another."""
        self.firewall.submit(
            ActionRequest(
                session_id="sess_alpha",
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            )
        )
        state_alpha = self.firewall._get_state("sess_alpha")
        state_beta = self.firewall._get_state("sess_beta")
        self.assertIsNotNone(state_alpha.bound_resource)
        self.assertIsNone(state_beta.bound_resource)

    def test_inv11_stateful_quota_enforcement(self):
        """
        INV-11: Stateful egress accumulation: data transfer rows/bytes are tracked in session state.
        Architecture Note: Egress counters are tracked monotonically in state; numerical quota
        limit enforcement is not implemented in the current baseline.
        """
        self.firewall.submit(
            ActionRequest(session_id="sess_inv11", tool="select_resource", arguments={"resource_ref": "public_records"})
        )
        self.firewall.submit(
            ActionRequest(session_id="sess_inv11", tool="configure_destination", arguments={"destination_ref": "internal_archive"})
        )
        res1 = self.firewall.submit(
            ActionRequest(session_id="sess_inv11", tool="execute_export", arguments={"rows": 500, "bytes": 10000})
        )
        self.assertEqual(res1.status, "EXECUTED")
        state1 = self.firewall._get_state("sess_inv11")
        self.assertEqual(state1.egress_counters["INTERNAL"].rows, 500)
        self.assertEqual(state1.egress_counters["INTERNAL"].bytes, 10000)

        # Successive transfer accumulates
        res2 = self.firewall.submit(
            ActionRequest(session_id="sess_inv11", tool="execute_export", arguments={"rows": 300, "bytes": 5000})
        )
        self.assertEqual(res2.status, "EXECUTED")
        state2 = self.firewall._get_state("sess_inv11")
        self.assertEqual(state2.egress_counters["INTERNAL"].rows, 800)
        self.assertEqual(state2.egress_counters["INTERNAL"].bytes, 15000)

    def test_inv12_lease_freshness_guarantee(self):
        """INV-12: State drift during review causes approval rejection (SEC-03)."""
        session_id = "sess_inv12"
        self.firewall.submit(
            ActionRequest(session_id=session_id, tool="select_resource", arguments={"resource_ref": "public_records"})
        )
        self.firewall.submit(
            ActionRequest(session_id=session_id, tool="configure_destination", arguments={"destination_ref": "external_storage"})
        )
        res = self.firewall.submit(
            ActionRequest(session_id=session_id, tool="execute_export", arguments={})
        )
        ticket_id = res.ticket_id
        self.assertIsNotNone(ticket_id)

        # Genuinely advance state using apply_event
        s_curr = self.firewall._get_state(session_id)
        drift_event = StateEventEnvelope(
            session_id=session_id,
            seq=s_curr.seq + 1,
            prior_head=s_curr.head_hash,
            event_type="EXECUTED",
            action_id=f"act_drift_{ticket_id}",
            token_id=f"tok_drift_{ticket_id}",
            payload={"tool": "select_resource", "arguments": {"resource_ref": "public_records"}},
        )
        self.firewall._states[session_id] = apply_event(s_curr, drift_event, self.registry, expected_session_id=session_id)

        approval_res = self.firewall.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="admin")
        self.assertEqual(approval_res.status, "DENIED")
        self.assertEqual(approval_res.decision, Decision.DENY)
        self.assertIn("STATE_CHANGED", approval_res.reason_codes[0])


if __name__ == "__main__":
    unittest.main()

"""AASF Security Invariants Regression Test Suite.

Automated regression suite formally evaluating Invariants INV-01 through INV-12:
- INV-01: Agent claims cannot create or elevate identity.
- INV-02: Registry facts cannot be overridden by agent parameters.
- INV-03: Policy PROHIBIT is absolute, non-overridable, and final.
- INV-04: Unknown tools and unresolvable destinations fail closed.
- INV-05: Human review approval must re-validate policy rules and state.
- INV-06: Cryptographic capability token single-use semantics.
- INV-07: Parameter integrity binding in execution tokens.
- INV-08: Fail-closed system default under ambiguous outcomes.
- INV-09: Tamper-evident hash chaining in the audit ledger.
- INV-10: Strict session state isolation and non-leakage.
- INV-11: Stateful quota and rate-limit enforcement.
- INV-12: Atomic lease revocation and freshness guarantees.
"""

import sys
import os
import unittest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
src_path = os.path.join(repo_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from firewall.core import FirewallCore, FirewallConfig
from firewall.models import (
    ToolAction,
    ActorContext,
    DecisionOutcome,
    PolicyOutcome,
    ToolClass
)
from firewall.execution.token_vault import TokenVault
from firewall.audit.ledger import AuditLedger


class TestSecurityInvariantsRegression(unittest.TestCase):
    """Formal verification tests for INV-01 through INV-12."""

    def setUp(self):
        self.config = FirewallConfig(
            enable_monitoring=False,
            enforce_state=True,
            strict_fail_closed=True
        )
        self.firewall = FirewallCore(self.config)

    def test_inv01_identity_elevation_rejected(self):
        """INV-01: Agent-supplied claims cannot create identity or permissions."""
        action = ToolAction(
            session_id="inv01_sess",
            actor=ActorContext(agent_id="unauthorized_actor", role="root"),
            tool_name="admin_shutdown",
            parameters={}
        )
        res = self.firewall.submit(action)
        self.assertEqual(res.outcome, DecisionOutcome.DENY)

    def test_inv02_registry_facts_immutable(self):
        """INV-02: Registry facts cannot be overridden by agent parameters."""
        action = ToolAction(
            session_id="inv02_sess",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="read_file",
            parameters={"path": "/data/report.txt", "claimed_classification": "BENIGN_PUBLIC"}
        )
        # Even if agent claims class is benign public, true registry classification is used
        res = self.firewall.submit(action)
        # Registry classification rules dictate the verdict, agent claim is ignored
        self.assertNotIn("claimed_classification", res.reason)

    def test_inv03_prohibit_non_overridable(self):
        """INV-03: Policy PROHIBIT is absolute and cannot be downgraded."""
        action = ToolAction(
            session_id="inv03_sess",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="format_disk",
            parameters={"target": "/dev/sda"}
        )
        res = self.firewall.submit(action)
        self.assertEqual(res.outcome, DecisionOutcome.DENY)

    def test_inv04_unknown_tools_fail_closed(self):
        """INV-04: Unknown tools fail closed to DENY."""
        action = ToolAction(
            session_id="inv04_sess",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="completely_nonexistent_tool_xyz",
            parameters={}
        )
        res = self.firewall.submit(action)
        self.assertEqual(res.outcome, DecisionOutcome.DENY)

    def test_inv05_review_revalidation_regression(self):
        """INV-05: Verifies whether review approval re-validates policy (Audits SEC-01)."""
        action = ToolAction(
            session_id="inv05_sess",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="fetch_url",
            parameters={"url": "http://192.0.2.1/unverified"}
        )
        res = self.firewall.submit(action)
        self.assertEqual(res.outcome, DecisionOutcome.REVIEW)
        ticket_id = res.review_ticket_id

        # In unpatched implementation, approve executes without policy revalidation:
        approval_res = self.firewall.resolve_review(ticket_id, decision="APPROVE", reviewer="admin")
        
        # DOCUMENTATION OF DEFECT SEC-01:
        # Expected secure behavior: should fail or re-evaluate policy.
        # Current behavior: issues token directly.
        self.assertIsNotNone(approval_res.execution_token)

    def test_inv06_token_single_use(self):
        """INV-06: Cryptographic token is consumed exactly once."""
        vault = TokenVault(secret_key="audit_test_key_32_bytes_long!!")
        tok = vault.mint_token("sess_inv06", "tool_a", {"k": "v"})
        
        # 1st consume: success
        self.assertTrue(vault.validate_and_consume(tok, "tool_a", {"k": "v"}))
        
        # 2nd consume: fails
        with self.assertRaises(Exception):
            vault.validate_and_consume(tok, "tool_a", {"k": "v"})

    def test_inv07_token_parameter_integrity(self):
        """INV-07: Token signature binds tool and parameters; tampering fails validation."""
        vault = TokenVault(secret_key="audit_test_key_32_bytes_long!!")
        tok = vault.mint_token("sess_inv07", "tool_a", {"k": "v"})
        
        # Consuming with modified parameters must fail
        with self.assertRaises(Exception):
            vault.validate_and_consume(tok, "tool_a", {"k": "tampered_value"})

    def test_inv08_fail_closed_default(self):
        """INV-08: System defaults to fail-closed on missing rules."""
        action = ToolAction(
            session_id="inv08_sess",
            actor=ActorContext(agent_id="unknown_agent", role="unregistered_role"),
            tool_name="read_file",
            parameters={"path": "/data/test.txt"}
        )
        res = self.firewall.submit(action)
        self.assertEqual(res.outcome, DecisionOutcome.DENY)

    def test_inv09_tamper_evident_audit_ledger(self):
        """INV-09: Any alteration to the ledger breaks the cryptographic hash chain."""
        ledger = AuditLedger()
        ledger.record_event("sess_inv09", "EVENT_1", {"msg": "initial"})
        ledger.record_event("sess_inv09", "EVENT_2", {"msg": "secondary"})
        self.assertTrue(ledger.verify_integrity())

        # Mutate prior hash
        ledger.events[1].previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(ledger.verify_integrity())

    def test_inv10_session_isolation(self):
        """INV-10: State mutations in one session do not bleed into another."""
        tracker = self.firewall.state_tracker
        tracker.initialize_session("sess_alpha", quota_bytes=500)
        tracker.initialize_session("sess_beta", quota_bytes=500)
        
        tracker.record_data_transfer("sess_alpha", 400)
        state_alpha = tracker.get_session_state("sess_alpha")
        state_beta = tracker.get_session_state("sess_beta")

        self.assertEqual(state_alpha.cumulative_transfer_bytes, 400)
        self.assertEqual(state_beta.cumulative_transfer_bytes, 0)

    def test_inv11_stateful_quota_enforcement(self):
        """INV-11: Quotas are strictly enforced once exhausted."""
        tracker = self.firewall.state_tracker
        tracker.initialize_session("sess_inv11", quota_bytes=100)
        
        # Valid transfer
        self.assertTrue(tracker.can_transfer("sess_inv11", 50))
        tracker.record_data_transfer("sess_inv11", 50)
        
        # Second valid transfer
        self.assertTrue(tracker.can_transfer("sess_inv11", 50))
        tracker.record_data_transfer("sess_inv11", 50)
        
        # Exceeds quota
        self.assertFalse(tracker.can_transfer("sess_inv11", 1))

    def test_inv12_lease_freshness_guarantee(self):
        """INV-12: Leases expire accurately and block post-expiration access."""
        tracker = self.firewall.state_tracker
        tracker.initialize_session("sess_inv12")
        tracker.grant_lease("sess_inv12", resource="/secure/vault", duration_sec=-1)
        
        self.assertFalse(tracker.has_active_lease("sess_inv12", "/secure/vault"))


if __name__ == "__main__":
    unittest.main()


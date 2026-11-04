"""
AASF Adversarial Security Test Suite (Canonical Implementation).

Executes and verifies 20 structured adversarial attack scenarios (SC-01 to SC-20)
against the canonical AASF FirewallCore, TokenStore, and PolicyEngine.
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
from firewall.contracts.models import ActionRequest, CanonicalAction, ResourceRef
from firewall.core import FirewallCore
from firewall.executor.tokens import (
    TokenBindingMismatchError,
    TokenExpiredError,
    TokenReusedError,
    TokenStore,
)
from firewall.state.engine import StateEventEnvelope, apply_event
from firewall.state.registry import Registry


class TestAdversarialScenarios(unittest.TestCase):
    """20 Structured Adversarial Test Scenarios evaluated against the canonical runtime."""

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
                "delete_database": {"tool_class": "DESTRUCTIVE"},
            },
        )
        self.firewall = FirewallCore(registry=self.registry)

    def test_sc01_benign_authorized_tool(self):
        """SC-01: Baseline benign read action within authorized permissions."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_01",
                tool="select_resource",
                arguments={"resource_ref": "public_records"},
            )
        )
        self.assertEqual(res.status, "EXECUTED")
        self.assertEqual(res.decision, Decision.ALLOW)
        self.assertIsNotNone(res.result)

    def test_sc02_unregistered_tool_name(self):
        """SC-02: Attacker attempts to call an unregistered tool name."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_02",
                tool="system_exec_unregistered",
                arguments={"cmd": "whoami"},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertTrue(any("UNKNOWN_TOOL" in r for r in res.reason_codes))
        self.assertIsNone(res.result)

    def test_sc03_role_identity_spoofing(self):
        """SC-03: Agent claims admin role but lacks registered authorization."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_03",
                tool="relabel_resource",
                arguments={"resource_ref": "customer_records", "role": "superadmin"},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertEqual(res.policy_verdict, PolicyVerdict.PROHIBIT)
        self.assertIsNone(res.result)

    def test_sc04_explicit_prohibit_rule(self):
        """SC-04: Action matching an explicit policy PROHIBIT rule (R1)."""
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_04",
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            )
        )
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_04",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_04",
                tool="execute_export",
                arguments={},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertTrue(any("POLICY_PROHIBIT:R1" in r for r in res.reason_codes))
        self.assertIsNone(res.result)

    def test_sc05_path_traversal_parameter_tampering(self):
        """
        SC-05: Path traversal attack using dot-dot sequences.
        Protection Mechanism: Authoritative Resource Registry Whitelisting.
        Note: The firewall does not perform deep path normalization on arbitrary strings;
        instead, protection is enforced because unlisted traversal targets fail registry lookup.
        """
        traversal_payload = "/data/reports/../../../../etc/shadow"
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_05",
                tool="select_resource",
                arguments={"resource_ref": traversal_payload},
            )
        )
        # Registry does not contain the traversal path; state marks classification as UNKNOWN
        state = self.firewall._get_state("sess_adv_05")
        self.assertIsNotNone(state.bound_resource)
        self.assertEqual(state.bound_resource.classification, Classification.UNKNOWN)
        self.assertTrue(any("UNKNOWN_CLASSIFICATION" in str(a) for a in state.anomalies))

        # Subsequent export to external destination fails closed because resource is UNKNOWN
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_05",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        export_res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_05",
                tool="execute_export",
                arguments={},
            )
        )
        self.assertNotEqual(export_res.decision, Decision.ALLOW)
        self.assertIsNone(export_res.result)  # Tool execution prevented

    def test_sc06_single_use_token_replay(self):
        """SC-06: Attacker attempts to replay an already-consumed execution token."""
        store = self.firewall.token_store
        token = store.issue_token("act_adv_06", "hash_06", "head_06", "dec_06")

        # First consumption must succeed
        consumed = store.consume_token(token.token_id, "act_adv_06", "hash_06", "head_06")
        self.assertEqual(consumed.token_id, token.token_id)

        # Second consumption must fail at token store level (INV-06)
        with self.assertRaises(TokenReusedError):
            store.consume_token(token.token_id, "act_adv_06", "hash_06", "head_06")

        # Second execution attempt via ControlledExecutor is prevented
        action = CanonicalAction(
            action_id="act_adv_06",
            session_id="sess_adv_06",
            seq=1,
            tool="select_resource",
            arguments={"resource_ref": "public_records"},
            action_hash="hash_06",
        )
        envelope, _ = self.firewall.executor.execute(token, action, current_state_head="head_06")
        self.assertFalse(envelope.has_value)
        self.assertIsNotNone(envelope.error)
        self.assertEqual(envelope.error["code"], "TOKEN_ERROR")
        self.assertIn("already been consumed", envelope.error["message"])

    def test_sc07_token_parameter_substitution(self):
        """SC-07: Attacker attempts to use token for modified action hash."""
        store = self.firewall.token_store
        token = store.issue_token("act_adv_07", "hash_07", "head_07", "dec_07")

        with self.assertRaises(TokenBindingMismatchError):
            store.consume_token(token.token_id, "act_adv_07", "tampered_hash_value", "head_07")

    def test_sc08_token_expiration(self):
        """SC-08: Attacker attempts to consume an expired execution token at store level."""
        store = self.firewall.token_store
        token = store.issue_token("act_adv_08", "hash_08", "head_08", "dec_08", ttl_ms=-5000)

        with self.assertRaises(TokenExpiredError):
            store.consume_token(token.token_id, "act_adv_08", "hash_08", "head_08")

    def test_sc09_unregistered_destination_exfiltration(self):
        """
        SC-09: Network egress request to unapproved IP/domain.
        Architecture Note: Unapproved destinations cannot be verified against the
        registry; missing destination facts cause the policy engine to fail closed
        to human review rather than permitting egress.
        """
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_09",
                tool="select_resource",
                arguments={"resource_ref": "public_records"},
            )
        )
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_09",
                tool="configure_destination",
                arguments={"destination_ref": "http://198.51.100.44/exfil"},
            )
        )
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_09",
                tool="execute_export",
                arguments={},
            )
        )
        # Unapproved destination zone cannot be verified -> fails closed to REVIEW
        self.assertEqual(res.status, "PENDING_REVIEW")
        self.assertEqual(res.decision, Decision.REVIEW)
        self.assertIsNotNone(res.ticket_id)
        self.assertIsNone(res.result)

    def test_sc10_cumulative_transfer_quota_exhaustion(self):
        """
        SC-10: Cumulative data transfer rows/bytes are tracked in session state.
        Architecture Note: The state engine accurately accumulates egress counters per zone,
        establishing the state foundation for egress accounting. Numerical quota limit
        enforcement is not implemented in the current baseline.
        """
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_10",
                tool="select_resource",
                arguments={"resource_ref": "public_records"},
            )
        )
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_10",
                tool="configure_destination",
                arguments={"destination_ref": "internal_archive"},
            )
        )
        # First export transfer: 500 rows, 30000 bytes
        res1 = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_10",
                tool="execute_export",
                arguments={"rows": 500, "bytes": 30000},
            )
        )
        self.assertEqual(res1.status, "EXECUTED")
        state1 = self.firewall._get_state("sess_adv_10")
        self.assertEqual(state1.egress_counters["INTERNAL"].rows, 500)
        self.assertEqual(state1.egress_counters["INTERNAL"].bytes, 30000)

        # Second export transfer: 300 rows, 20000 bytes (accumulates monotonically)
        res2 = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_10",
                tool="execute_export",
                arguments={"rows": 300, "bytes": 20000},
            )
        )
        self.assertEqual(res2.status, "EXECUTED")
        state2 = self.firewall._get_state("sess_adv_10")
        self.assertEqual(state2.egress_counters["INTERNAL"].rows, 800)
        self.assertEqual(state2.egress_counters["INTERNAL"].bytes, 50000)

    def test_sc11_audit_log_tamper_detection(self):
        """SC-11: Modifying or truncating an audit log entry invalidates the cryptographic hash chain."""
        audit = self.firewall.audit_store
        audit.append("sess_adv_11", "ACTION_REQUEST", {"tool": "select_resource"})
        audit.append("sess_adv_11", "ACTION_EXECUTED", {"tool": "select_resource"})
        self.assertTrue(audit.verify_chain("sess_adv_11"))

        # 1. Tamper with record payload -> breaks hash continuity
        audit._records[0] = audit._records[0].model_copy(update={"payload": {"tool": "malicious"}})
        self.assertFalse(audit.verify_chain("sess_adv_11"))

        # 2. Ledger truncation (deleting genesis record) -> breaks genesis continuity
        audit_fresh = AuditStore()
        audit_fresh.append("sess_adv_11_trunc", "ACTION_REQUEST", {"tool": "select_resource"})
        audit_fresh.append("sess_adv_11_trunc", "ACTION_EXECUTED", {"tool": "select_resource"})
        self.assertTrue(audit_fresh.verify_chain("sess_adv_11_trunc"))
        audit_fresh._records.pop(0)  # Drop genesis record
        self.assertFalse(audit_fresh.verify_chain("sess_adv_11_trunc"))

    def test_sc12_review_approval_missing_evidence_flaw(self):
        """SC-12: Demonstrates fix for SEC-01: approval re-evaluates policy."""
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_12",
                tool="select_resource",
                arguments={"resource_ref": "public_records"},
            )
        )
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_12",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_12",
                tool="execute_export",
                arguments={},
            )
        )
        ticket_id = res.ticket_id

        # Mutate state to CONFIDENTIAL export (strictly PROHIBIT by R1)
        state = self.firewall._get_state("sess_adv_12")
        self.firewall._states["sess_adv_12"] = state.model_copy(
            update={
                "bound_resource": ResourceRef(
                    ref="customer_records",
                    classification=Classification.CONFIDENTIAL,
                    selected_seq=1,
                )
            }
        )
        self.firewall._ticket_state_heads[ticket_id] = self.firewall._get_state("sess_adv_12").head_hash

        resolved = self.firewall.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="sec_analyst")
        self.assertEqual(resolved.status, "DENIED")
        self.assertEqual(resolved.decision, Decision.DENY)
        self.assertIn("POLICY_PROHIBIT_ON_APPROVAL", resolved.reason_codes)
        self.assertIsNone(resolved.result)

    def test_sc13_stale_ticket_race(self):
        """SC-13: Demonstrates fix for SEC-03: approval detects state drift (TOCTOU)."""
        session_id = "sess_adv_13"
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

        # Concurrently advance state via apply_event
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

        resolved = self.firewall.resolve_review(ticket_id, outcome="APPROVE", reviewer_id="sec_analyst")
        self.assertEqual(resolved.status, "DENIED")
        self.assertEqual(resolved.decision, Decision.DENY)
        self.assertIn("STATE_CHANGED", resolved.reason_codes[0])
        self.assertIsNone(resolved.result)

    def test_sc14_concurrent_token_mint_isolation(self):
        """SC-14: Independent sessions do not leak or collide token nonces."""
        store = self.firewall.token_store
        tok1 = store.issue_token("sess_a", "read_file", "head_a", "dec_a")
        tok2 = store.issue_token("sess_b", "read_file", "head_b", "dec_b")
        self.assertNotEqual(tok1.nonce, tok2.nonce)
        self.assertNotEqual(tok1.token_id, tok2.token_id)

    def test_sc15_injection_in_json_parameters(self):
        """
        SC-15: Stacked SQL / Command injection attempt in structured fields.
        Protection Mechanism: Authoritative Registry Whitelisting and Dispatch Boundary.
        Note: The firewall does not parse or sanitize raw SQL; rather, attempts to inject
        arbitrary database commands fail because unlisted tools and injected resource
        names fail closed at the registry boundary.
        """
        injection_payload = "customer_records; DROP TABLE users;--"
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_15",
                tool="select_resource",
                arguments={"resource_ref": injection_payload},
            )
        )
        # Payload does not match registered resource; state marks classification as UNKNOWN
        state = self.firewall._get_state("sess_adv_15")
        self.assertIsNotNone(state.bound_resource)
        self.assertEqual(state.bound_resource.classification, Classification.UNKNOWN)
        self.assertTrue(any("UNKNOWN_CLASSIFICATION" in str(a) for a in state.anomalies))

        # Attempt to invoke unregistered SQL execution tool directly
        res_sql = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_15",
                tool="query_database",
                arguments={"query": "SELECT * FROM users; DROP TABLE users;--"},
            )
        )
        self.assertEqual(res_sql.status, "DENIED")
        self.assertEqual(res_sql.decision, Decision.DENY)
        self.assertTrue(any("UNKNOWN_TOOL" in r for r in res_sql.reason_codes))
        self.assertIsNone(res_sql.result)  # Tool never executed

    def test_sc16_lease_time_expiration(self):
        """SC-16: Action executed via ControlledExecutor with an expired token fails immediately."""
        store = self.firewall.token_store
        tok = store.issue_token("act_16", "hash_16", "head_16", "dec_16", ttl_ms=-1000)
        action = CanonicalAction(
            action_id="act_16",
            session_id="sess_adv_16",
            seq=1,
            tool="select_resource",
            arguments={"resource_ref": "public_records"},
            action_hash="hash_16",
        )
        envelope, receipt = self.firewall.executor.execute(tok, action, current_state_head="head_16")
        self.assertFalse(envelope.has_value)
        self.assertIsNotNone(envelope.error)
        self.assertEqual(envelope.error["code"], "TOKEN_ERROR")
        self.assertIn("expired", envelope.error["message"])
        self.assertIsNone(receipt)

    def test_sc17_toxic_tool_combination(self):
        """SC-17: Sequence read_sensitive followed immediately by external egress."""
        # Step 1: Read confidential data (permitted to build context)
        res1 = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_17",
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            )
        )
        self.assertEqual(res1.status, "EXECUTED")

        # Step 2: Configure external destination
        res2 = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_17",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        self.assertEqual(res2.status, "EXECUTED")

        # Step 3: Attempt external egress of confidential data -> blocked by Rule R1
        res3 = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_17",
                tool="execute_export",
                arguments={},
            )
        )
        self.assertEqual(res3.status, "DENIED")
        self.assertEqual(res3.decision, Decision.DENY)
        self.assertTrue(any("POLICY_PROHIBIT:R1" in r for r in res3.reason_codes))
        self.assertIsNone(res3.result)

    def test_sc18_privilege_escalation_via_parameter_mutation(self):
        """SC-18: Agent attempts to downgrade confidentiality classification via relabel."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_18",
                tool="relabel_resource",
                arguments={"resource_ref": "customer_records", "classification": "PUBLIC"},
            )
        )
        self.assertEqual(res.status, "DENIED")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertEqual(res.policy_verdict, PolicyVerdict.PROHIBIT)
        self.assertIsNone(res.result)

    def test_sc19_empty_parameter_bypass(self):
        """SC-19: Omission of required resource reference fails to bind state, logs anomaly, and halts export."""
        res = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_19",
                tool="select_resource",
                arguments={},
            )
        )
        state = self.firewall._get_state("sess_adv_19")
        self.assertIsNone(state.bound_resource)
        self.assertTrue(any("UNKNOWN_CLASSIFICATION" in str(a) for a in state.anomalies))
        self.assertGreater(state.indeterminate_state, 0)

        # Downstream export to external destination fails closed because no valid resource was bound
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_19",
                tool="configure_destination",
                arguments={"destination_ref": "external_storage"},
            )
        )
        res_exp = self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_19",
                tool="execute_export",
                arguments={},
            )
        )
        self.assertNotEqual(res_exp.decision, Decision.ALLOW)
        self.assertIsNone(res_exp.result)

    def test_sc20_cross_session_state_leakage(self):
        """SC-20: State in session A cannot satisfy requirements in session B."""
        self.firewall.submit(
            ActionRequest(
                session_id="sess_adv_20_a",
                tool="select_resource",
                arguments={"resource_ref": "customer_records"},
            )
        )
        state_a = self.firewall._get_state("sess_adv_20_a")
        state_b = self.firewall._get_state("sess_adv_20_b")
        self.assertIsNotNone(state_a.bound_resource)
        self.assertIsNone(state_b.bound_resource)


if __name__ == "__main__":
    unittest.main()

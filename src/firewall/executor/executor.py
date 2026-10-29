"""
Controlled Executor (C6) for AI Agent Permission Firewall.
Enforces INV-05 and INV-06:
- Actions execute only after valid single-use authorization token consumption.
- Never executes tool requests directly without token validation.
- Emits signed EvidenceReceipt for state-relevant executions.
Source: 05_TECHNICAL_SPEC.md §3.2, 01_THREAT_MODEL.md (INV-05, INV-06, INV-07)
"""

import time
from typing import Any, Callable, Optional

from firewall.contracts.enums import ConfirmationLevel, OutcomeContract
from firewall.contracts.models import (
    AuthorizationToken,
    CanonicalAction,
    EvidenceReceipt,
    ResultEnvelope,
)
from firewall.executor.tokens import TokenError, TokenStore
from firewall.state.evidence import HmacEvidenceVerifier


class ControlledExecutor:
    """
    Controlled tool execution gateway.
    Rejects unauthorized, replayed, expired, or mismatched tool executions.
    """

    def __init__(
        self,
        token_store: TokenStore,
        verifier: Optional[HmacEvidenceVerifier] = None,
    ) -> None:
        self.token_store = token_store
        self.verifier = verifier or HmacEvidenceVerifier(key=b"firewall_trusted_executor_key")
        self._tool_handlers: dict[
            str, Callable[[CanonicalAction], tuple[Any, Optional[dict[str, Any]]]]
        ] = {}
        self._register_default_handlers()

    def register_tool_handler(
        self,
        tool_name: str,
        handler: Callable[[CanonicalAction], tuple[Any, Optional[dict[str, Any]]]],
    ) -> None:
        """Register a handler for a specific tool."""
        self._tool_handlers[tool_name] = handler

    def _register_default_handlers(self) -> None:
        """Register default simulated handlers for core data-export benchmark tools."""

        def select_resource_handler(
            action: CanonicalAction,
        ) -> tuple[Any, Optional[dict[str, Any]]]:
            res_ref = action.arguments.get("resource_ref", "")
            return {"selected": res_ref}, None

        def create_export_job_handler(
            action: CanonicalAction,
        ) -> tuple[Any, Optional[dict[str, Any]]]:
            job_id = f"job_{action.action_id[:8]}"
            return {"job_id": job_id, "created": True}, None

        def configure_destination_handler(
            action: CanonicalAction,
        ) -> tuple[Any, Optional[dict[str, Any]]]:
            dest_ref = action.arguments.get("destination_ref", "")
            return {"destination": dest_ref}, None

        def execute_export_handler(action: CanonicalAction) -> tuple[Any, Optional[dict[str, Any]]]:
            # Returns execution result plus observed state for evidence receipt
            rows = action.arguments.get("rows", 5000)
            bytes_count = action.arguments.get("bytes", 200000)
            obs = {"rows": rows, "bytes": bytes_count}
            return {"exported_rows": rows, "status": "COMPLETED"}, obs

        def validate_schema_handler(
            action: CanonicalAction,
        ) -> tuple[Any, Optional[dict[str, Any]]]:
            return {"schema_valid": True, "message": "Schema valid."}, None

        self._tool_handlers["select_resource"] = select_resource_handler
        self._tool_handlers["create_export_job"] = create_export_job_handler
        self._tool_handlers["configure_destination"] = configure_destination_handler
        self._tool_handlers["execute_export"] = execute_export_handler
        self._tool_handlers["validate_schema"] = validate_schema_handler

    def execute(
        self,
        token: AuthorizationToken,
        action: CanonicalAction,
        current_state_head: str,
        now_ms: Optional[int] = None,
    ) -> tuple[ResultEnvelope, Optional[EvidenceReceipt]]:
        """
        Executes a canonical action after validating and consuming the single-use token.
        Guarantees:
        - Atomically consumes token; rejects reused, expired, or mismatched tokens (INV-06).
        - Generates HMAC-signed EvidenceReceipt if tool yields observable state.
        """
        curr_time = now_ms if now_ms is not None else int(time.time() * 1000)

        # 1. Validate and consume token atomically
        try:
            self.token_store.consume_token(
                token_id=token.token_id,
                expected_action_id=action.action_id,
                expected_action_hash=action.action_hash,
                expected_state_head_hash=current_state_head,
                now_ms=curr_time,
            )
        except TokenError as te:
            envelope = ResultEnvelope(
                has_value=False,
                value=None,
                error={"code": "TOKEN_ERROR", "message": str(te)},
                outcome_contract=OutcomeContract.SYNCHRONOUS_CONFIRMED,
                confirmation_level=ConfirmationLevel.NONE,
            )
            return envelope, None

        # 2. Look up tool handler
        handler = self._tool_handlers.get(action.tool)
        if handler is None:
            envelope = ResultEnvelope(
                has_value=False,
                value=None,
                error={
                    "code": "UNKNOWN_TOOL",
                    "message": f"Tool '{action.tool}' has no registered executor handler",
                },
                outcome_contract=OutcomeContract.SYNCHRONOUS_CONFIRMED,
                confirmation_level=ConfirmationLevel.NONE,
            )
            return envelope, None

        # 3. Execute tool handler
        try:
            val, obs_state = handler(action)

            envelope = ResultEnvelope(
                has_value=True,
                value=val,
                error=None,
                outcome_contract=OutcomeContract.SYNCHRONOUS_CONFIRMED,
                confirmation_level=ConfirmationLevel.CONFIRMED_COMPLETED,
            )

            receipt: Optional[EvidenceReceipt] = None
            if obs_state is not None:
                receipt = self.verifier.create_signed_receipt(
                    session_id=action.session_id,
                    action_id=action.action_id,
                    token_id=token.token_id,
                    source_tool_name=action.tool,
                    observed_state=obs_state,
                    observed_timestamp_ms=curr_time,
                )

            return envelope, receipt

        except Exception as e:
            envelope = ResultEnvelope(
                has_value=False,
                value=None,
                error={"code": "EXECUTION_FAILURE", "message": str(e)},
                outcome_contract=OutcomeContract.SYNCHRONOUS_CONFIRMED,
                confirmation_level=ConfirmationLevel.NONE,
            )
            return envelope, None

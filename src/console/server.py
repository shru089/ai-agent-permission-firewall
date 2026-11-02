"""
FastAPI Server for the AASF Interactive Security Console.
Exposes REST endpoints for the Agent Simulator, Firewall Inspector,
Human Review Console, Audit Explorer, and Preset Scenarios.
"""

import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from console.adapter import ConsoleRuntimeAdapter

app = FastAPI(
    title="AASF Interactive Security Console",
    description=(
        "Real-time mediation, inspection, and human oversight console "
        "for the Adaptive Agentic Security Firewall."
    ),
    version="0.1.0",
)

# Enable CORS for local cross-origin development if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global shared runtime adapter instance
runtime_adapter = ConsoleRuntimeAdapter()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class SubmitActionPayload(BaseModel):
    session_id: str = Field(default="demo_session_interactive")
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    context_notes: str = Field(default="")


class ResolveReviewPayload(BaseModel):
    outcome: str = Field(..., description="'APPROVE' or 'REJECT'")
    reviewer_id: str = Field(default="sec_analyst_alice")


class TamperPayload(BaseModel):
    session_id: str


@app.get("/")
def serve_index() -> FileResponse:
    """Serve the single-page application dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Frontend console not built yet.")
    return FileResponse(index_path)


@app.get("/api/health")
def health_check() -> dict[str, Any]:
    """Health check endpoint confirming live connection to FirewallCore."""
    return {
        "status": "ONLINE",
        "firewall": "FirewallCore In-Process Reference Monitor",
        "invariants_enforced": 12,
        "contracts_version": "0.1.0",
    }


@app.get("/api/tools")
def list_tools() -> list[dict[str, Any]]:
    """List all safe allowlisted tools and their risk classifications."""
    tools = runtime_adapter.registry._tools
    result = []
    for tool_name, tool_info in tools.items():
        result.append(
            {
                "name": tool_name,
                "tool_class": tool_info.tool_class.value,
                "description": f"Tool class: {tool_info.tool_class.value}",
            }
        )
    return result


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, str]]:
    """List all 10 required demonstration scenarios."""
    return runtime_adapter.list_scenarios()


@app.post("/api/scenarios/run/{scenario_id}")
def run_scenario(scenario_id: str, custom_session: Optional[str] = None) -> dict[str, Any]:
    """Execute one of the 10 preset demonstration scenarios."""
    res = runtime_adapter.run_preset_scenario(scenario_id, custom_session)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res


@app.post("/api/action/submit")
def submit_action(payload: SubmitActionPayload) -> dict[str, Any]:
    """Submit an action request through FirewallCore and return full 9-step trace."""
    return runtime_adapter.submit_action(
        session_id=payload.session_id,
        tool=payload.tool,
        arguments=payload.arguments,
        context_notes=payload.context_notes,
    )


@app.get("/api/session/{session_id}/state")
def get_session_state(session_id: str) -> dict[str, Any]:
    """Retrieve observable session state, taint, and cryptographic head hash."""
    return runtime_adapter.get_session_state(session_id)


@app.get("/api/session/{session_id}/audit")
def get_session_audit(session_id: str) -> dict[str, Any]:
    """Retrieve audit trail records and cryptographic hash-chain verification."""
    return runtime_adapter.get_audit_trail(session_id)


@app.post("/api/audit/tamper-demo")
def tamper_audit(payload: TamperPayload) -> dict[str, Any]:
    """Simulate deliberate audit record tampering to demonstrate INV-09."""
    return runtime_adapter.demonstrate_tamper(payload.session_id)


@app.post("/api/audit/restore")
def restore_audit(payload: TamperPayload) -> dict[str, Any]:
    """Restore tampered audit record from backup."""
    return runtime_adapter.restore_audit_tamper(payload.session_id)


@app.get("/api/reviews/pending")
def list_pending_reviews() -> list[dict[str, Any]]:
    """List all tickets awaiting human oversight."""
    return runtime_adapter.list_pending_reviews()


@app.post("/api/reviews/{ticket_id}/resolve")
def resolve_review(ticket_id: str, payload: ResolveReviewPayload) -> dict[str, Any]:
    """Resolve a review ticket as APPROVE or REJECT."""
    return runtime_adapter.resolve_review(
        ticket_id=ticket_id,
        outcome=payload.outcome,
        reviewer_id=payload.reviewer_id,
    )

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"

class ActionRequest(BaseModel):
    """The standardized input for every guard in the cascade."""
    request_id: str
    user_id: str
    tool_name: str
    arguments: Dict[str, Any]
    content_payload: str  # The actual text being checked for IPI
    timestamp: datetime = Field(default_factory=datetime.now)

class ActionVerdict(BaseModel):
    """The standardized output from every guard."""
    decision: Decision
    reason_code: str  # e.g., "DET_BLACKLIST_MATCH", "LLM_INJECTION_DETECTED"
    guard_id: str     # Which tier caught it? (Deterministic, Lightweight, Deep)
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None

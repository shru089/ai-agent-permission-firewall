"""
Canonical JSON serialization and action hashing for AI Agent Permission Firewall.
Contracts Version: 0.1.0
Source: 05_TECHNICAL_SPEC.md §4, RFC 8785 (JSON Canonicalization Scheme)
"""

import hashlib
import unicodedata
from enum import Enum
from typing import Any

import rfc8785
from pydantic import BaseModel

DEFAULT_CONTRACTS_VERSION = "0.1.0"


def _normalize_value(val: Any, reject_floats: bool = True) -> Any:
    """
    Recursively normalizes strings to Unicode NFC and optionally rejects floating-point numbers.
    Supports primitives, dicts, lists, Enums, and Pydantic BaseModels.
    """
    if isinstance(val, BaseModel):
        return _normalize_value(val.model_dump(mode="python"), reject_floats=reject_floats)
    if isinstance(val, float):
        if reject_floats:
            raise ValueError(
                f"Floating-point numbers are prohibited in canonical action arguments; "
                f"received float: {val}. Use exact integers or string representations instead."
            )
        return val
    if isinstance(val, str):
        return unicodedata.normalize("NFC", val)
    if isinstance(val, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normalize_value(v, reject_floats=reject_floats)
            for k, v in sorted(
                val.items(), key=lambda item: unicodedata.normalize("NFC", str(item[0]))
            )
        }
    if isinstance(val, (list, tuple)):
        return [_normalize_value(elem, reject_floats=reject_floats) for elem in val]
    if isinstance(val, Enum):
        return _normalize_value(val.value, reject_floats=reject_floats)
    if isinstance(val, (int, bool)) or val is None:
        return val
    return val


def canonical_json(data: Any, reject_floats: bool = True) -> bytes:
    """
    Serializes a data structure to canonical RFC 8785 JSON bytes.
    - Unicode NFC normalization applied to all strings and keys.
    - Floats rejected if reject_floats=True (default).
    - Lexicographically sorted keys.
    - No insignificant whitespace.
    """
    normalized = _normalize_value(data, reject_floats=reject_floats)
    return rfc8785.dumps(normalized)


def canonical_hash(data: Any, reject_floats: bool = False) -> str:
    """Computes SHA-256 over canonical RFC 8785 JSON bytes."""
    return hashlib.sha256(canonical_json(data, reject_floats=reject_floats)).hexdigest()


def sha256_hex(data: bytes | str) -> str:
    """Computes SHA-256 hex digest of raw bytes or UTF-8 string."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


canonical_sha256 = canonical_hash


def compute_action_hash(
    session_id: str,
    seq: int,
    tool: str,
    arguments: dict[str, Any],
    version: str = DEFAULT_CONTRACTS_VERSION,
) -> str:
    """
    Computes canonical SHA-256 action hash according to 05_TECHNICAL_SPEC.md §4:
    action_hash = SHA-256(
        canonical_json({"v": version, "session_id": ..., "seq": ..., "tool": ..., "args": ...})
    )
    """
    preimage = {
        "v": version,
        "session_id": unicodedata.normalize("NFC", session_id),
        "seq": seq,
        "tool": unicodedata.normalize("NFC", tool),
        "args": arguments,
    }
    canonical_bytes = canonical_json(preimage, reject_floats=True)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_genesis_head(session_id: str) -> str:
    """Computes initial genesis state head hash for a new session."""
    session_norm = unicodedata.normalize("NFC", session_id)
    return hashlib.sha256(f"GENESIS:{session_norm}".encode("utf-8")).hexdigest()

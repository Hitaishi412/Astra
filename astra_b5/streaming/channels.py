"""
streaming/channels.py
──────────────────────
Channel naming convention and message envelope for the streaming layer.

Conventions:
    All channels are namespaced per-session so multiple sessions can run
    simultaneously without crosstalk.

    Format: "astra:{session_id}:{stream}"

    Example:  astra:abc123:logs
              astra:abc123:alerts
              astra:abc123:attack_status
              astra:abc123:scores
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ─── Channel types ──────────────────────────────────────────────────────────
class StreamType(str, Enum):
    """The streams a session can publish to."""
    LOGS = "logs"                  # Block 3 → publishes log entries
    ALERTS = "alerts"              # Block 4 → publishes alerts
    ATTACK_STATUS = "attack_status"  # Block 2 → publishes kill chain progress
    SCORES = "scores"              # Block 5 → publishes score updates
    CONTROL = "control"            # System messages: pause/resume/abort
    HEARTBEAT = "heartbeat"        # Keep-alive pings


# ─── Channel name builders ──────────────────────────────────────────────────
def channel_for(session_id: str, stream: StreamType) -> str:
    """Build the canonical channel name for a session+stream."""
    return f"astra:{session_id}:{stream.value}"


def all_channels_for(session_id: str) -> list[str]:
    """Return every channel for a session — useful for full-session subscribers."""
    return [channel_for(session_id, st) for st in StreamType]


def parse_channel(channel: str) -> Optional[tuple[str, str]]:
    """
    Parse 'astra:abc123:logs' → ('abc123', 'logs').
    Returns None if the format is invalid.
    """
    parts = channel.split(":")
    if len(parts) != 3 or parts[0] != "astra":
        return None
    return parts[1], parts[2]


# ─── Message envelope ───────────────────────────────────────────────────────
def envelope(stream: StreamType, payload: dict[str, Any]) -> dict[str, Any]:
    """
    Wrap a payload in a standard message envelope. Every message published to
    a stream channel goes through this so consumers have consistent metadata.
    """
    return {
        "stream": stream.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }


def serialize(message: dict[str, Any]) -> str:
    """JSON-serialize a message for Redis/WebSocket transport."""
    return json.dumps(message, default=_json_default)


def deserialize(data: str | bytes) -> dict[str, Any]:
    """Decode a JSON message from the wire."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data)


def _json_default(obj: Any) -> Any:
    """Handle non-JSON-native types (datetime, etc.)."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):  # Pydantic v2
        return obj.model_dump(mode="json")
    if hasattr(obj, "dict"):  # Pydantic v1 fallback
        return obj.dict()
    return str(obj)

"""
streaming/publisher.py
───────────────────────
Typed publishers for each stream type.

Other blocks call these instead of touching channels/backend directly:

    await publish_log(session_id, log_entry)
    await publish_alert(session_id, alert)
    await publish_attack_status(session_id, kill_chain_summary)
    await publish_score(session_id, score)
    await publish_control(session_id, "pause")
"""

from __future__ import annotations

from typing import Any, Optional

from streaming.backend import get_backend
from streaming.channels import StreamType, channel_for, envelope, serialize


# ─── Generic publish ────────────────────────────────────────────────────────
async def publish(
    session_id: str,
    stream: StreamType,
    payload: dict[str, Any] | Any,
) -> int:
    """
    Publish a payload to the given stream for a session.
    Returns the number of subscribers that received it.
    """
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json")
    elif not isinstance(payload, dict):
        payload = {"value": str(payload)}

    msg = envelope(stream, payload)
    channel = channel_for(session_id, stream)
    return await get_backend().publish(channel, serialize(msg))


# ─── Typed convenience wrappers ─────────────────────────────────────────────
async def publish_log(session_id: str, log_entry: Any) -> int:
    """Publish a LogEntry (or dict) to the logs channel."""
    return await publish(session_id, StreamType.LOGS, log_entry)


async def publish_alert(session_id: str, alert: Any) -> int:
    """Publish an AlertSchema (or dict) to the alerts channel."""
    return await publish(session_id, StreamType.ALERTS, alert)


async def publish_attack_status(session_id: str, status: dict[str, Any]) -> int:
    """
    Publish kill chain progress to the attack_status channel.
    `status` is typically the output of orchestrator.kill_chain_summary.
    """
    return await publish(session_id, StreamType.ATTACK_STATUS, status)


async def publish_score(session_id: str, score: Any) -> int:
    """Publish a score update."""
    return await publish(session_id, StreamType.SCORES, score)


async def publish_control(
    session_id: str,
    command: str,
    extra: Optional[dict[str, Any]] = None,
) -> int:
    """
    Publish a control message (pause, resume, abort, etc.)
    `command` is a short string the consumer interprets.
    """
    payload = {"command": command, **(extra or {})}
    return await publish(session_id, StreamType.CONTROL, payload)


async def publish_heartbeat(session_id: str, info: Optional[dict] = None) -> int:
    """Publish a heartbeat ping for keep-alive monitoring."""
    return await publish(session_id, StreamType.HEARTBEAT, info or {"ok": True})


# ─── Bulk publish ───────────────────────────────────────────────────────────
async def publish_logs_bulk(session_id: str, log_entries: list[Any]) -> int:
    """
    Publish multiple log entries efficiently.
    Returns total subscribers reached across all messages.
    """
    total = 0
    for entry in log_entries:
        total += await publish_log(session_id, entry)
    return total

"""
api/routers/logs.py
────────────────────
Logs endpoints — paginated query + real-time WebSocket stream.

Routes:
    GET   /logs                           — paginated logs (filter by session_id)
    GET   /logs/stats/{session_id}        — log statistics for a session
    WS    /logs/stream/{session_id}       — real-time WebSocket log feed

The WebSocket endpoint also supports streams=alerts,attack_status query param
to subscribe to multiple streams in one connection.
"""

from __future__ import annotations

import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.schemas.streaming import LogEntryResponse, LogStatsResponse
from db import crud
from streaming.channels import StreamType
from streaming.manager import get_ws_manager


logger = logging.getLogger("astra.logs_router")
router = APIRouter()


# ════════════════════════════════════════════════════════════════════════════
# REST  —  paginated logs
# ════════════════════════════════════════════════════════════════════════════
@router.get("", response_model=list[LogEntryResponse])
async def list_logs(
    session_id: str,
    source: str | None = None,
    is_malicious: bool | None = None,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List logs for a session with optional filters."""
    logs = await crud.get_logs(
        db,
        session_id=session_id,
        source=source,
        is_malicious=is_malicious,
        limit=limit,
        offset=offset,
    )
    return logs


# ════════════════════════════════════════════════════════════════════════════
# REST  —  stats
# ════════════════════════════════════════════════════════════════════════════
@router.get("/stats/{session_id}", response_model=LogStatsResponse)
async def log_stats(session_id: str, db: AsyncSession = Depends(get_db)):
    """Statistical summary of logs in a session."""
    logs = await crud.get_logs(db, session_id=session_id, limit=10_000)

    if not logs:
        return LogStatsResponse(
            session_id=session_id,
            total=0,
            by_source={},
            by_severity={},
            malicious_count=0,
            benign_count=0,
        )

    return LogStatsResponse(
        session_id=session_id,
        total=len(logs),
        by_source=dict(Counter(l.source for l in logs)),
        by_severity=dict(Counter(l.severity for l in logs)),
        malicious_count=sum(1 for l in logs if l.is_malicious),
        benign_count=sum(1 for l in logs if not l.is_malicious),
    )


# ════════════════════════════════════════════════════════════════════════════
# WEBSOCKET  —  real-time stream
# ════════════════════════════════════════════════════════════════════════════
@router.websocket("/stream/{session_id}")
async def stream_logs(
    websocket: WebSocket,
    session_id: str,
    streams: str = Query("logs", description="Comma-separated stream names"),
):
    """
    Real-time stream of events for a session.

    The `streams` query parameter selects which streams the client wants:
        ?streams=logs                       (just logs)
        ?streams=logs,alerts                (logs + alerts)
        ?streams=logs,alerts,attack_status  (everything)

    All messages come wrapped in the standard envelope:
        {"stream": "logs", "timestamp": "...", "payload": {...}}
    """
    requested_names = [s.strip() for s in streams.split(",") if s.strip()]
    valid: list[StreamType] = []
    for name in requested_names:
        try:
            valid.append(StreamType(name))
        except ValueError:
            logger.warning(f"[logs/stream] unknown stream '{name}', skipping")

    if not valid:
        await websocket.close(code=4400, reason="No valid streams requested")
        return

    mgr = get_ws_manager()
    await mgr.connect(websocket, session_id=session_id, streams=valid)

    try:
        # Hold the connection open. Client → server messages are ignored for
        # now — the dashboard could later send control commands here.
        while True:
            try:
                _ = await websocket.receive_text()
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    finally:
        await mgr.disconnect(websocket)

"""
api/routers/logs.py
────────────────────
Logs endpoints — paginated query + real-time WebSocket stream.

Routes:
    GET   /logs                           — paginated logs (filter by session_id)
    GET   /logs/stats/{session_id}        — log statistics for a session
    WS    /logs/stream/{session_id}       — real-time WebSocket log feed

Auth:
  REST endpoints require a token and verify session ownership (404 otherwise).
  The WebSocket can't carry an Authorization header (browsers don't allow it),
  so it authenticates from a `?token=<firebase_id_token>` query param, then
  enforces the same session-ownership check before streaming. In dev fallback
  (Firebase disabled) it resolves to the demo user, matching the REST path.

  Note: the token rides in the query string, which can appear in proxy/server
  access logs. Firebase ID tokens are short-lived (~1h), which limits the
  exposure; if you want to avoid query-string logging entirely, switch to
  first-message auth (client sends the token as its first WS frame). Happy to
  wire that variant instead.
"""

from __future__ import annotations

import logging
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import _init_firebase, _verify_firebase_token, get_current_user
from api.ownership import verify_session_owner
from api.schemas.streaming import LogEntryResponse, LogStatsResponse
from db import crud
from db.models import User
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
    offset: int = Query(0, ge=0, le=10_000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List logs for a session with optional filters."""
    await verify_session_owner(db, session_id, current_user)

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
async def log_stats(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Statistical summary of logs in a session."""
    await verify_session_owner(db, session_id, current_user)

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
# WEBSOCKET  —  auth helper
# ════════════════════════════════════════════════════════════════════════════
async def _ws_authenticate(websocket: WebSocket, db: AsyncSession) -> User | None:
    """Resolve the User for a WebSocket connection.

    A browser WebSocket can't send an Authorization header, so we read the
    Firebase ID token from the `?token=` query param. Returns the User, or
    None if authentication fails. In dev fallback (Firebase disabled) returns
    the seeded demo user, matching the REST get_current_user behaviour.
    """
    # Dev fallback: Firebase intentionally disabled -> demo user.
    try:
        firebase_active = _init_firebase()
    except Exception:
        # Firebase is configured but failed to initialise -> fail closed.
        return None

    if not firebase_active:
        result = await db.execute(select(User).where(User.username == "demo"))
        return result.scalar_one_or_none()

    token = websocket.query_params.get("token")
    if not token:
        return None

    try:
        decoded = await _verify_firebase_token(token)
    except Exception:
        return None

    uid = decoded.get("uid")
    if not uid:
        return None

    result = await db.execute(select(User).where(User.firebase_uid == uid))
    return result.scalar_one_or_none()


# ════════════════════════════════════════════════════════════════════════════
# WEBSOCKET  —  real-time stream
# ════════════════════════════════════════════════════════════════════════════
@router.websocket("/stream/{session_id}")
async def stream_logs(
    websocket: WebSocket,
    session_id: str,
    streams: str = Query("logs", description="Comma-separated stream names"),
    db: AsyncSession = Depends(get_db),
):
    """
    Real-time stream of events for a session.

    Connect with the Firebase ID token in the query string:
        /logs/stream/<session_id>?streams=logs,alerts&token=<id_token>

    The `streams` query parameter selects which streams the client wants:
        ?streams=logs                       (just logs)
        ?streams=logs,alerts                (logs + alerts)
        ?streams=logs,alerts,attack_status  (everything)

    All messages come wrapped in the standard envelope:
        {"stream": "logs", "timestamp": "...", "payload": {...}}

    Close codes: 4401 = unauthenticated, 4403 = not your session,
    4400 = no valid streams requested.
    """
    # 1. Authenticate (closes before accept on failure → handshake rejected).
    user = await _ws_authenticate(websocket, db)
    if user is None:
        await websocket.close(code=4401)
        return

    # 2. Ownership: the session must belong to the authenticated user.
    session = await crud.get_session(db, session_id)
    if session is None or session.user_id != user.id:
        await websocket.close(code=4403)
        return

    # 3. Resolve requested streams.
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
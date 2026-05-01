"""
Alert endpoints — query alerts and triage them.

Routes:
    GET  /alerts                       — list alerts (filter by session_id, severity, status)
    GET  /alerts/{alert_id}            — get a single alert
    PATCH /alerts/{alert_id}/triage    — triage an alert (mark TP/FP, add notes)
    GET  /alerts/stats/{session_id}    — alert statistics for a session
"""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.schemas.detection import AlertResponse, AlertTriage
from db import crud
from db.models import Alert

router = APIRouter()


# ─── List ────────────────────────────────────────────────────────────────────
@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    session_id: str | None = None,
    severity: str | None = None,
    triage_status: str | None = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List alerts. Most useful when filtered by session_id."""
    if session_id:
        alerts = await crud.get_alerts(
            db,
            session_id=session_id,
            severity=severity,
            triage_status=triage_status,
            limit=limit,
        )
    else:
        # Get most recent across all sessions
        stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if triage_status:
            stmt = stmt.where(Alert.triage_status == triage_status)
        result = await db.execute(stmt)
        alerts = list(result.scalars().all())

    return alerts


# ─── Get one ─────────────────────────────────────────────────────────────────
@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


# ─── Triage ──────────────────────────────────────────────────────────────────
@router.patch("/{alert_id}/triage", response_model=AlertResponse)
async def triage_alert(
    alert_id: str,
    body: AlertTriage,
    db: AsyncSession = Depends(get_db),
):
    """
    Triage an alert — mark it as investigating / true positive / false positive,
    and add analyst notes.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    await crud.triage_alert(
        db,
        alert_id=alert_id,
        triage_status=body.triage_status,
        analyst_notes=body.analyst_notes,
        is_true_positive=body.is_true_positive,
    )

    # Reload to return fresh state
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one()


# ─── Stats ───────────────────────────────────────────────────────────────────
@router.get("/stats/{session_id}")
async def alert_stats(session_id: str, db: AsyncSession = Depends(get_db)):
    """Return alert statistics for a session — counts by severity, triage status, etc."""
    alerts = await crud.get_alerts(db, session_id=session_id, limit=10_000)

    if not alerts:
        return {
            "session_id": session_id,
            "total": 0,
            "by_severity": {},
            "by_status": {},
            "by_detection_type": {},
            "true_positives": 0,
            "false_positives": 0,
            "pending_triage": 0,
        }

    by_severity = Counter(a.severity for a in alerts)
    by_status = Counter(a.triage_status for a in alerts)
    by_detection_type = Counter(a.detection_type for a in alerts)
    tp = sum(1 for a in alerts if a.is_true_positive is True)
    fp = sum(1 for a in alerts if a.is_true_positive is False)
    pending = sum(1 for a in alerts if a.triage_status == "new")

    return {
        "session_id": session_id,
        "total": len(alerts),
        "by_severity": dict(by_severity),
        "by_status": dict(by_status),
        "by_detection_type": dict(by_detection_type),
        "true_positives": tp,
        "false_positives": fp,
        "pending_triage": pending,
    }

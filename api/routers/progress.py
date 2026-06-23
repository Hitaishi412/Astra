"""
api/routers/progress.py
────────────────────────
Progress endpoints — feeds the Progress page on the dashboard.

SECURITY: every route resolves the user from get_current_user (the
Firebase token), NOT from a URL parameter. There is no {user_id} in any
path — a caller can only ever read their own progress. This removes the
IDOR class entirely (no object reference to tamper with) rather than
guarding it. The old /progress/users directory endpoint was removed: it
enumerated every user's id+username to any caller.

Routes (all scoped to the authenticated user):
    GET /progress/summary    — top-level stats
    GET /progress/trends     — score time series + mode breakdown
    GET /progress/skills     — avg sub-scores
    GET /progress/tactics    — per-tactic detection rates
    GET /progress/activity   — last 30 days of session counts
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from db.models import Score, Session as SessionModel, User

router = APIRouter()


@router.get("/summary")
async def user_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Top-level stats for the authenticated user."""
    user_id = current_user.id
    stmt = (
        select(Score)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
    )
    result = await db.execute(stmt)
    scores = result.scalars().all()

    if not scores:
        return {
            "user_id": user_id,
            "total_sessions": 0,
            "avg_score": 0.0,
            "best_score": 0.0,
            "avg_coverage": 0.0,
        }

    return {
        "user_id": user_id,
        "total_sessions": len(scores),
        "avg_score": round(sum(s.total_score for s in scores) / len(scores), 1),
        "best_score": round(max(s.total_score for s in scores), 1),
        "avg_coverage": round(
            sum(s.mitre_coverage_pct for s in scores) / len(scores), 1
        ),
    }


@router.get("/trends")
async def user_trends(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Score over time, with mode tag for each session."""
    user_id = current_user.id
    stmt = (
        select(Score, SessionModel)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
        .order_by(Score.created_at.asc())
        .limit(50)
    )
    result = await db.execute(stmt)
    rows = []
    for score, session in result.all():
        mode = "soc"
        meta = getattr(session, "config", None)
        if isinstance(meta, dict):
            mode = meta.get("mode", "soc")
        rows.append({
            "session_id": session.id,
            "scenario": session.scenario_id,
            "score": float(score.total_score),
            "grade": score.grade,
            "coverage": float(score.mitre_coverage_pct),
            "mode": mode,
            "date": score.created_at.isoformat() if score.created_at else None,
        })
    return rows


@router.get("/skills")
async def user_skills(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Average of each sub-score across the user's sessions."""
    user_id = current_user.id
    stmt = (
        select(Score)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
    )
    result = await db.execute(stmt)
    scores = result.scalars().all()

    if not scores:
        return {"detection": 0, "mttd": 0, "fp_rate": 0, "containment": 0, "report": 0, "coverage": 0}

    n = len(scores)
    return {
        "detection":   round(sum(s.detection_rate              for s in scores) / n, 1),
        "mttd":        round(sum(_mttd_to_score(s.mean_time_to_detect_sec) for s in scores) / n, 1),
        "fp_rate":     round(sum(_fp_to_score(s.false_positive_rate) for s in scores) / n, 1),
        "containment": round(sum(s.containment_score           for s in scores) / n, 1),
        "report":      round(sum(s.report_quality_score        for s in scores) / n, 1),
        "coverage":    round(sum(s.mitre_coverage_pct          for s in scores) / n, 1),
    }


@router.get("/tactics")
async def user_tactics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-tactic detection rates aggregated across sessions."""
    user_id = current_user.id
    stmt = (
        select(Score)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
    )
    result = await db.execute(stmt)
    scores = result.scalars().all()

    tactic_used: dict[str, int] = defaultdict(int)
    tactic_detected: dict[str, int] = defaultdict(int)

    for score in scores:
        details = score.details or {}
        by_tactic = details.get("by_tactic") or details.get("mitre", {}).get("by_tactic", {})
        if not isinstance(by_tactic, dict):
            continue
        for tactic, stats in by_tactic.items():
            if isinstance(stats, dict):
                tactic_used[tactic] += int(stats.get("used", 0))
                tactic_detected[tactic] += int(stats.get("detected", 0))

    return {
        tactic: {
            "used": tactic_used[tactic],
            "detected": tactic_detected[tactic],
            "detection_rate": (tactic_detected[tactic] / tactic_used[tactic]) if tactic_used[tactic] else 0.0,
            "sessions_seen": len(scores),
        }
        for tactic in sorted(tactic_used.keys())
    }


@router.get("/activity")
async def user_activity(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sessions per day for the last 30 days, broken down by mode."""
    user_id = current_user.id
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stmt = (
        select(Score, SessionModel)
        .join(SessionModel, SessionModel.id == Score.session_id)
        .where(SessionModel.user_id == user_id)
        .where(Score.created_at >= cutoff)
    )
    result = await db.execute(stmt)

    counts: dict[tuple[str, str], int] = defaultdict(int)
    for score, session in result.all():
        if not score.created_at:
            continue
        date_str = score.created_at.date().isoformat()
        meta = getattr(session, "config", None) or {}
        mode = meta.get("mode", "soc") if isinstance(meta, dict) else "soc"
        counts[(date_str, mode)] += 1

    return [
        {"date": d, "mode": m, "count": c}
        for (d, m), c in sorted(counts.items())
    ]


def _mttd_to_score(mttd_sec: float) -> float:
    if mttd_sec <= 0:
        return 100.0
    if mttd_sec <= 60:
        return 100.0
    if mttd_sec <= 600:
        return 80.0
    if mttd_sec <= 1800:
        return 50.0
    return 20.0


def _fp_to_score(fp_rate: float) -> float:
    if fp_rate <= 0:
        return 100.0
    if fp_rate >= 0.5:
        return 0.0
    return max(0.0, 100.0 - fp_rate * 200.0)

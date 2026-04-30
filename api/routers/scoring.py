"""
api/routers/scoring.py
───────────────────────
Score and leaderboard endpoints.

Routes:
    GET /scoring/sessions/{session_id}     — get score for a specific session
    GET /scoring/leaderboard                — top scoring sessions
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.schemas.streaming import LeaderboardEntry, ScoreResponse
from db import crud
from db.models import Score, Session as SessionModel, User

router = APIRouter()


@router.get("/sessions/{session_id}", response_model=ScoreResponse)
async def get_session_score(session_id: str, db: AsyncSession = Depends(get_db)):
    """Get the score record for a session."""
    score = await crud.get_score(db, session_id)
    if score is None:
        raise HTTPException(
            status_code=404,
            detail=f"No score recorded for session '{session_id}' yet. "
                   f"Score is generated when the session completes.",
        )
    return score


@router.get("/leaderboard", response_model=list[LeaderboardEntry])
async def get_leaderboard(
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the top-scoring sessions.

    Joins session + user data so the dashboard can show usernames + scenarios.
    """
    stmt = (
        select(Score, SessionModel, User)
        .join(SessionModel, Score.session_id == SessionModel.id)
        .join(User, SessionModel.user_id == User.id)
        .order_by(Score.total_score.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)

    entries = []
    for rank, (score, session, user) in enumerate(result.all(), start=1):
        entries.append(LeaderboardEntry(
            rank=rank,
            session_id=session.id,
            username=user.username,
            scenario_id=session.scenario_id,
            total_score=score.total_score,
            grade=score.grade,
            mitre_coverage_pct=score.mitre_coverage_pct,
        ))
    return entries

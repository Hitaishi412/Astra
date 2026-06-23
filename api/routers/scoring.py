"""
api/routers/scoring.py
───────────────────────
Score and leaderboard endpoints.

SECURITY:
  - Both routes require a valid Firebase token (get_current_user).
  - /scoring/sessions/{session_id} enforces ownership: the session must
    belong to the caller, else 404 (404 not 403 — don't confirm the id
    exists to non-owners).
  - /scoring/leaderboard is intentionally cross-user (a leaderboard shows
    everyone's top scores by design) but still requires login, so it
    can't be scraped anonymously.

Routes:
    GET /scoring/sessions/{session_id}  — score for a session you own
    GET /scoring/leaderboard            — top scoring sessions (all users)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from api.schemas.streaming import LeaderboardEntry, ScoreResponse
from db import crud
from db.models import Score, Session as SessionModel, User

router = APIRouter()


@router.get("/sessions/{session_id}", response_model=ScoreResponse)
async def get_session_score(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the score record for a session the caller owns."""
    # Ownership check FIRST: confirm this session belongs to current_user.
    own = await db.execute(
        select(SessionModel.id).where(
            SessionModel.id == session_id,
            SessionModel.user_id == current_user.id,
        )
    )
    if own.first() is None:
        # 404 (not 403) so we don't reveal whether the session exists.
        raise HTTPException(
            status_code=404,
            detail=f"No score recorded for session '{session_id}' yet. "
                   f"Score is generated when the session completes.",
        )

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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the top-scoring sessions across all users.

    Cross-user by design (it's a leaderboard) but login-gated so it
    can't be scraped anonymously.
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

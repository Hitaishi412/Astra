"""
Session endpoints — create, get, list, and update training sessions.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.schemas.session import SessionCreate, SessionResponse, SessionStatusUpdate
from api.schemas.scenario import SCENARIO_REGISTRY
from db import crud

router = APIRouter()


@router.post("", response_model=SessionResponse, status_code=201)
async def create_session(body: SessionCreate, db: AsyncSession = Depends(get_db)):
    """Start a new training session."""

    # Validate scenario exists
    if body.scenario_id not in SCENARIO_REGISTRY:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{body.scenario_id}'. "
                   f"Available: {list(SCENARIO_REGISTRY.keys())}",
        )

    # Validate difficulty is supported by this scenario
    scenario = SCENARIO_REGISTRY[body.scenario_id]
    if body.difficulty not in scenario["difficulty_range"]:
        raise HTTPException(
            status_code=400,
            detail=f"Scenario '{body.scenario_id}' supports difficulties: "
                   f"{scenario['difficulty_range']}",
        )

    # Get or create user
    user = await crud.get_or_create_user(db, body.username)

    # Create session
    session = await crud.create_session(
        db,
        user_id=user.id,
        scenario_id=body.scenario_id,
        role=body.role,
        difficulty=body.difficulty,
    )

    return session


@router.get("", response_model=list[SessionResponse])
async def list_sessions(
    username: str | None = None,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List recent sessions, optionally filtered by username."""
    user_id = None
    if username:
        user = await crud.get_user_by_username(db, username)
        if user is None:
            return []
        user_id = user.id

    sessions = await crud.list_sessions(db, user_id=user_id, limit=limit)
    return sessions


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific session by ID."""
    session = await crud.get_session(db, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.patch("/{session_id}", response_model=dict)
async def update_session_status(
    session_id: str,
    body: SessionStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update session status (start, pause, complete, abort)."""
    session = await crud.get_session(db, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    # Validate state transitions
    valid_transitions = {
        "created": ["running", "aborted"],
        "running": ["paused", "completed", "aborted"],
        "paused": ["running", "completed", "aborted"],
        "completed": [],
        "aborted": [],
    }

    if body.status not in valid_transitions.get(session.status, []):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition from '{session.status}' to '{body.status}'. "
                   f"Valid transitions: {valid_transitions[session.status]}",
        )

    await crud.update_session_status(db, session_id, body.status)
    return {"message": f"Session status updated to '{body.status}'", "session_id": session_id}

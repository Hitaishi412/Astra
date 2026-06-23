"""
Session endpoints — create, get, list, and update training sessions.

Auth note:
  Every endpoint now resolves the acting user from `get_current_user`
  (Firebase token in production; the seeded `demo` user in local dev
  when FIREBASE_ENABLED=false). The session always belongs to the
  authenticated user — `SessionCreate.username` is accepted for
  backward compatibility but ignored. Read/mutate endpoints enforce
  ownership so a user cannot touch another user's sessions.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from api.schemas.session import SessionCreate, SessionResponse, SessionStatusUpdate
from api.schemas.scenario import SCENARIO_REGISTRY
from db import crud
from db.models import User


# Pentester scenarios live in a separate registry — import lazily and
# tolerate ImportError so this router still works if Pentester mode
# isn't installed.
def _pentester_scenario_ids() -> set[str]:
    try:
        from core.pentester import list_scenarios as pentester_list
        return {s["scenario_id"] for s in pentester_list()}
    except Exception:
        return set()


router = APIRouter()


@router.post("", response_model=SessionResponse, status_code=201)
async def create_session(
    body: SessionCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start a new training session.

    Accepts scenario_ids from both the SOC registry (api.schemas.scenario)
    and the Pentester registry (core.pentester). Pentester scenarios
    skip difficulty-range validation because each pentester scenario IS
    a specific difficulty (silver_pixel=easy, op_greenfield=medium,
    nexus_infiltration=hard).

    The session is created for the authenticated user. `body.username`
    is ignored — identity comes from the auth token (or the demo user
    in local dev).
    """

    pentester_ids = _pentester_scenario_ids()
    is_pentester = body.scenario_id in pentester_ids

    # Validate scenario exists in either registry
    if body.scenario_id not in SCENARIO_REGISTRY and not is_pentester:
        all_known = list(SCENARIO_REGISTRY.keys()) + sorted(pentester_ids)
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{body.scenario_id}'. "
                   f"Available: {all_known}",
        )

    # Validate difficulty (only for SOC scenarios; pentester scenarios are
    # difficulty-fixed by their scenario_id)
    if not is_pentester:
        scenario = SCENARIO_REGISTRY[body.scenario_id]
        if body.difficulty not in scenario["difficulty_range"]:
            raise HTTPException(
                status_code=400,
                detail=f"Scenario '{body.scenario_id}' supports difficulties: "
                       f"{scenario['difficulty_range']}",
            )

    # User is the authenticated identity, NOT whatever the body claims.
    session = await crud.create_session(
        db,
        user_id=current_user.id,
        scenario_id=body.scenario_id,
        role=body.role,
        difficulty=body.difficulty,
    )

    return session


@router.get("", response_model=list[SessionResponse])
async def list_sessions(
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the authenticated user's recent sessions."""
    sessions = await crud.list_sessions(db, user_id=current_user.id, limit=limit)
    return sessions


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific session by ID (must belong to the current user)."""
    session = await crud.get_session(db, session_id)
    # 404 (not 403) when it isn't theirs, so we don't leak which
    # session IDs exist for other users.
    if session is None or session.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.patch("/{session_id}", response_model=dict)
async def update_session_status(
    session_id: str,
    body: SessionStatusUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update session status (start, pause, complete, abort).

    The session must belong to the authenticated user.
    """
    session = await crud.get_session(db, session_id)
    if session is None or session.user_id != current_user.id:
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

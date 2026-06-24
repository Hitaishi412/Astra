"""
api/routers/attacks.py
───────────────────────
Attack Engine API endpoints.

POST   /attacks/load                   — load a scenario (stepwise mode)
POST   /attacks/next                   — execute next step (stepwise mode)
POST   /attacks/run/{scenario_id}      — run full scenario, stream steps as NDJSON
GET    /attacks/status                 — current scenario status + kill chain summary
POST   /attacks/abort                  — abort running scenario

Each session has its own AttackOrchestrator instance, so multiple sessions
can run concurrently without interfering.

Auth note:
  Every endpoint resolves the acting user from `get_current_user` and verifies
  (via `_verify_session_owner`) that the supplied session_id belongs to that
  user before doing anything with it. We return 404 (not 403) when a session
  isn't theirs, so we never reveal which session ids exist for other users.
  Matches the convention in pentester.py / sessions.py / scoring.py.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from db import crud
from db.models import User
from core.attack_engine.orchestrator import AttackOrchestrator
from core.session_driver import (
    SessionDriver,
    register_driver,
    register_task,
    get_driver,
    get_task,
    drop_driver,
)

logger = logging.getLogger("astra.api.attacks")
router = APIRouter()


# ─── Per-session orchestrator registry ────────────────────────────────────────
# Each session gets its own orchestrator so two concurrent sessions can each
# have their own loaded scenario without clobbering each other.
_orchestrators: dict[str, AttackOrchestrator] = {}
_orchestrators_lock = threading.Lock()


def _get_orchestrator(session_id: str) -> AttackOrchestrator:
    """Get or create the orchestrator for a session."""
    with _orchestrators_lock:
        orch = _orchestrators.get(session_id)
        if orch is None:
            orch = AttackOrchestrator()
            _orchestrators[session_id] = orch
        return orch


def _drop_orchestrator(session_id: str) -> None:
    """Remove the orchestrator for a session (after completion or abort)."""
    with _orchestrators_lock:
        _orchestrators.pop(session_id, None)


async def _verify_session_owner(db: AsyncSession, session_id: str, current_user: User):
    """Verify the session exists AND belongs to current_user, returning it.

    Raises 404 on both "not found" and "not yours" (deliberately not 403) so we
    never reveal whether a session id exists for another user. Mirrors the
    helper in pentester.py / scoring.py.
    """
    session = await crud.get_session(db, session_id)
    if session is None or session.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


# ─── Request / Response models ────────────────────────────────────────────────

class LoadRequest(BaseModel):
    session_id:    str
    scenario_id:   str
    difficulty:    str = "medium"
    target_ip:     Optional[str] = None
    target_domain: str = "corp.internal"
    step_delay_ms: int = 800   # ms between steps in streaming mode


class NextStepRequest(BaseModel):
    session_id: str


class AbortRequest(BaseModel):
    session_id: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _step_to_db_payload(step, session_id: str) -> dict:
    """Convert an AttackStep → dict ready for crud.create_attack_event()."""
    return {
        "session_id":     session_id,
        "phase":          step.phase,
        "step_number":    step.step_number,
        "technique_id":   step.technique_id,
        "technique_name": step.technique_name,
        "tactic":         step.tactic,
        "description":    step.description,
        "source_host":    step.source_host,
        "target_host":    str(step.target_host) if step.target_host else None,
        "success":        step.success,
        "extra_data":     step.extra_data,
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/load")
async def load_scenario(
    body: LoadRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Load a scenario into stepwise mode for a given session.
    After this call, use POST /attacks/next to execute one step at a time.
    """
    # Verify the session exists AND belongs to the caller
    session = await _verify_session_owner(db, body.session_id, current_user)
    if session.status not in ("created", "running"):
        raise HTTPException(status_code=400, detail=f"Session is '{session.status}' — cannot load scenario")

    orch = _get_orchestrator(body.session_id)

    try:
        metadata = orch.load(
            scenario_id=body.scenario_id,
            difficulty=body.difficulty,
            target_ip=body.target_ip,
            target_domain=body.target_domain,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Mark session as running
    await crud.update_session_status(db, body.session_id, "running")

    return {
        "message":  f"Scenario '{body.scenario_id}' loaded. Call POST /attacks/next to begin.",
        "scenario": metadata,
    }


@router.post("/next")
async def next_step(
    body: NextStepRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Execute the next technique in the loaded scenario for this session.
    Returns the AttackStep details and saves an AttackEvent to the DB.
    Returns {"done": true} when the scenario is complete.
    """
    # Verify ownership before revealing whether a scenario is loaded
    await _verify_session_owner(db, body.session_id, current_user)

    orch = _orchestrators.get(body.session_id)
    if orch is None or not orch.is_loaded:
        raise HTTPException(
            status_code=400,
            detail="No scenario loaded for this session. Call POST /attacks/load first.",
        )

    step = orch.next_step()

    if step is None:
        # Scenario complete — mark session done
        await crud.update_session_status(db, body.session_id, "completed")
        kill_chain = orch.kill_chain_summary
        campaign = orch.campaign_context
        _drop_orchestrator(body.session_id)
        return {
            "done":             True,
            "message":          "Scenario complete.",
            "kill_chain":       kill_chain,
            "campaign_context": campaign,
        }

    # Persist AttackEvent to DB
    await crud.create_attack_event(db, **_step_to_db_payload(step, body.session_id))

    return {
        "done": False,
        "step": {
            "id":             step.id,
            "step_number":    step.step_number,
            "phase":          step.phase,
            "technique_id":   step.technique_id,
            "technique_name": step.technique_name,
            "tactic":         step.tactic,
            "description":    step.description,
            "source_host":    step.source_host,
            "target_host":    str(step.target_host) if step.target_host else None,
            "success":        step.success,
            "severity":       step.severity,
            "log_count_hint": step.log_count_hint,
            "timestamp":      step.timestamp.isoformat(),
            "extra_data":     step.extra_data,
        },
        "kill_chain": orch.kill_chain_summary,
    }


@router.post("/run/{scenario_id}", status_code=202)
async def run_scenario_stream(
    scenario_id:   str,
    session_id:    str,
    current_user:  User = Depends(get_current_user),
    difficulty:    str = "medium",
    target_ip:     Optional[str] = None,
    step_delay_ms: int = 800,
    db: AsyncSession = Depends(get_db),
):
    """
    Launch a full scenario as a background task.

    The SessionDriver runs the attack and PUBLISHES logs/alerts/score/status
    to the streaming backend (Redis) as it progresses; the dashboard's
    subscriber receives those events and updates the live feed. Returns 202
    immediately the client does NOT consume an HTTP stream; the live data
    arrives out-of-band via the streaming backend.
    """
    await _verify_session_owner(db, session_id, current_user)
    await crud.update_session_status(db, session_id, "running")

    driver = SessionDriver(session_id=session_id)
    register_driver(session_id, driver)

    async def _drive():
        try:
            await driver.run(
                scenario_id=scenario_id,
                difficulty=difficulty,
                target_ip=target_ip,
                step_delay_ms=step_delay_ms,
            )
        except Exception:
            logger.exception(f"[attacks/run] driver crashed for session={session_id}")

    task = asyncio.create_task(_drive())
    register_task(session_id, task)

    return {"status": "started", "session_id": session_id, "scenario_id": scenario_id}


@router.get("/status")
async def attack_status(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return current scenario state and kill chain progress for a session."""
    await _verify_session_owner(db, session_id, current_user)

    orch = _orchestrators.get(session_id)
    if orch is None or not orch.is_loaded:
        return {"status": "idle", "loaded": False, "session_id": session_id}

    return {
        "status":           "running",
        "loaded":           True,
        "session_id":       session_id,
        "kill_chain":       orch.kill_chain_summary,
        "campaign_context": orch.campaign_context,
    }


@router.post("/abort")
async def abort_scenario(
    body: AbortRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Abort the running scenario for a session and mark it aborted."""
    await _verify_session_owner(db, body.session_id, current_user)

    # New path: a background SessionDriver is running this session.
    driver = get_driver(body.session_id)
    if driver is not None:
        driver.abort()
        task = get_task(body.session_id)
        if task is not None:
            task.cancel()
        drop_driver(body.session_id)
    # Legacy/manual path: a bare orchestrator started via /load + /next.
    orch = _orchestrators.get(body.session_id)
    if orch is not None:
        orch.abort()
        _drop_orchestrator(body.session_id)

    await crud.update_session_status(db, body.session_id, "aborted")

    return {"status": "aborted", "session_id": body.session_id}
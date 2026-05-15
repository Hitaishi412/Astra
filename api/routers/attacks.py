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
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from db import crud
from core.attack_engine.orchestrator import AttackOrchestrator
import asyncio
from core.session_driver import (
    SessionDriver,
    drop_driver,
    get_driver,
    register_driver,
    register_task,
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
async def load_scenario(body: LoadRequest, db: AsyncSession = Depends(get_db)):
    """
    Load a scenario into stepwise mode for a given session.
    After this call, use POST /attacks/next to execute one step at a time.
    """
    # Validate session exists
    session = await crud.get_session(db, body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
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
async def next_step(body: NextStepRequest, db: AsyncSession = Depends(get_db)):
    """
    Execute the next technique in the loaded scenario for this session.
    Returns the AttackStep details and saves an AttackEvent to the DB.
    Returns {"done": true} when the scenario is complete.
    """
    orch = _orchestrators.get(body.session_id)
    if orch is None or not orch.is_loaded:
        raise HTTPException(
            status_code=400,
            detail="No scenario loaded for this session. Call POST /attacks/load first.",
        )

    # Validate session exists
    session = await crud.get_session(db, body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

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
async def run_scenario_background(
    scenario_id:   str,
    session_id:    str,
    difficulty:    str = "medium",
    target_ip:     Optional[str] = None,
    step_delay_ms: int = 800,
    db:            AsyncSession = Depends(get_db),
):
    """
    Kick off a full Red→Blue session as a background task.
    Returns 202 immediately; driver pushes events to streaming channels.
    """
    session = await crud.get_session(db, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if get_driver(session_id) is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} is already running",
        )

    await crud.update_session_status(db, session_id, "running")

    driver = SessionDriver(session_id=session_id)
    register_driver(session_id, driver)

    task = asyncio.create_task(
        driver.run(
            scenario_id=scenario_id,
            difficulty=difficulty,
            target_ip=target_ip,
            step_delay_ms=step_delay_ms,
        ),
        name=f"session-driver:{session_id}",
    )
    register_task(session_id, task)

    def _on_done(t):
        if get_driver(session_id) is driver:
            drop_driver(session_id)
        if not t.cancelled():
            exc = t.exception()
            if exc is not None:
                logger.error(
                    f"[attacks] session {session_id} task ended with: "
                    f"{type(exc).__name__}: {exc}"
                )

    task.add_done_callback(_on_done)

    return {
        "status":      "accepted",
        "session_id":  session_id,
        "scenario_id": scenario_id,
        "difficulty":  difficulty,
        "message":     "Session started in background.",
    }

@router.get("/status")
async def attack_status(session_id: str):
    """Return current scenario state and kill chain progress for a session."""
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
async def abort_scenario(body: AbortRequest, db: AsyncSession = Depends(get_db)):
    """Abort the running scenario for a session and mark it aborted."""
    orch = _orchestrators.get(body.session_id)
    if orch is not None:
        orch.abort()
        _drop_orchestrator(body.session_id)

    session = await crud.get_session(db, body.session_id)
    if session:
        await crud.update_session_status(db, body.session_id, "aborted")

    return {"status": "aborted", "session_id": body.session_id}

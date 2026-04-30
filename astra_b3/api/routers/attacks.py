"""
api/routers/attacks.py
───────────────────────
Attack Engine API endpoints.

POST   /attacks/load                   — load a scenario (stepwise mode)
POST   /attacks/next                   — execute next step (stepwise mode)
POST   /attacks/run/{scenario_id}      — run full scenario, stream steps as NDJSON
GET    /attacks/status                 — current scenario status + kill chain summary
POST   /attacks/abort                  — abort running scenario

These endpoints connect the Attack Engine (Block 2) to the rest of the platform.
The Log Engine (Block 3) and MITRE Mapper (Block 5) hooks will be added
as those blocks are built — see TODO comments.
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from db import crud
from core.attack_engine.orchestrator import AttackOrchestrator
from core.log_engine.generator import LogGenerator
from core.log_engine.noise import NoiseGenerator

router  = APIRouter()
# Single shared orchestrator instance per process.
# In production: move to app state / dependency injection.
_orchestrator = AttackOrchestrator()
_log_gen      = LogGenerator()
_noise_gen    = NoiseGenerator()


# ─── Request / Response models ────────────────────────────────────────────────

class LoadRequest(BaseModel):
    session_id:   str
    scenario_id:  str
    difficulty:   str = "medium"
    target_ip:    Optional[str] = None
    target_domain: str = "corp.internal"
    step_delay_ms: int = 800   # ms between steps in streaming mode


class NextStepRequest(BaseModel):
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
    Load a scenario into stepwise mode.
    After this call, use POST /attacks/next to execute one step at a time.
    """
    # Validate session exists
    session = await crud.get_session(db, body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status not in ("created", "running"):
        raise HTTPException(status_code=400, detail=f"Session is '{session.status}' — cannot load scenario")

    try:
        metadata = _orchestrator.load(
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
    Execute the next technique in the loaded scenario.
    Returns the AttackStep details and saves an AttackEvent to the DB.
    Returns {"done": true} when the scenario is complete.
    """
    if not _orchestrator.is_loaded:
        raise HTTPException(status_code=400, detail="No scenario loaded. Call POST /attacks/load first.")

    # Validate session exists
    session = await crud.get_session(db, body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    step = _orchestrator.next_step()

    if step is None:
        # Scenario complete — mark session done
        await crud.update_session_status(db, body.session_id, "completed")
        return {
            "done":             True,
            "message":          "Scenario complete.",
            "kill_chain":       _orchestrator.kill_chain_summary,
            "campaign_context": _orchestrator.campaign_context,
        }

    # Persist AttackEvent to DB
    attack_event = await crud.create_attack_event(db, **_step_to_db_payload(step, body.session_id))

    # Block 3: generate synthetic logs + noise, persist them
    attack_logs = _log_gen.generate(step, session_id=body.session_id)
    noise_logs  = _noise_gen.burst(session_id=body.session_id, count=step.noise_count_hint)
    all_logs    = _noise_gen.interleave(attack_logs, noise_logs)
    if all_logs:
        await crud.bulk_create_log_entries(db, [l.to_db_dict() for l in all_logs])

    # TODO (Block 5): pass step to mitre_mapper.record(step) to track coverage

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
        "kill_chain": _orchestrator.kill_chain_summary,
    }


@router.post("/run/{scenario_id}")
async def run_scenario_stream(
    scenario_id:   str,
    session_id:    str,
    difficulty:    str = "medium",
    target_ip:     Optional[str] = None,
    step_delay_ms: int = 800,
    db: AsyncSession = Depends(get_db),
):
    """
    Stream a full scenario as newline-delimited JSON (NDJSON).
    Each line is one AttackStep JSON object.
    Use this to feed the WebSocket / dashboard live attack feed.

    Client reads: response.body line-by-line, parse each as JSON.
    """
    session = await crud.get_session(db, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    await crud.update_session_status(db, session_id, "running")

    async def _generate():
        step_num = 0
        async for step in _orchestrator.run_scenario_async(
            scenario_id=scenario_id,
            difficulty=difficulty,
            target_ip=target_ip,
            step_delay_ms=step_delay_ms,
        ):
            step_num += 1
            # Persist to DB (fire-and-forget — don't await in generator for simplicity)
            payload = _step_to_db_payload(step, session_id)

            data = {
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
                "timestamp":      step.timestamp.isoformat(),
                "extra_data":     step.extra_data,
            }
            yield json.dumps(data) + "\n"

        # Final summary line
        yield json.dumps({"done": True, "message": "Scenario complete"}) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


@router.get("/status")
async def attack_status():
    """Return current scenario state and kill chain progress."""
    if not _orchestrator.is_loaded:
        return {"status": "idle", "loaded": False}

    return {
        "status":           "running",
        "loaded":           True,
        "kill_chain":       _orchestrator.kill_chain_summary,
        "campaign_context": _orchestrator.campaign_context,
    }


@router.post("/abort")
async def abort_scenario(session_id: str, db: AsyncSession = Depends(get_db)):
    """Abort the running scenario and mark the session as aborted."""
    _orchestrator.abort()

    session = await crud.get_session(db, session_id)
    if session:
        await crud.update_session_status(db, session_id, "aborted")

    return {"status": "aborted"}

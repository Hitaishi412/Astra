"""
api/routers/mitre.py
─────────────────────
MITRE ATT&CK endpoints.

Routes:
    GET /mitre/technique/{technique_id}    — details for a single technique (public reference)
    GET /mitre/coverage/{session_id}       — ATT&CK coverage for a session you own
    GET /mitre/matrix                       — full enterprise matrix metadata (public reference)

technique/matrix read from the cached enterprise_attack.json — that's public
ATT&CK reference data, so they're unauthenticated. coverage/{session_id} reads
a specific session's attack events + alerts, so it requires auth + ownership.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from api.ownership import verify_session_owner
from api.schemas.streaming import CoverageResponse, TechniqueResponse
from db import crud
from db.models import User

router = APIRouter()


# ─── Lazy load of MITRE data ────────────────────────────────────────────────
_MITRE_PATH = Path(__file__).parent.parent.parent / "core" / "mitre" / "data" / "enterprise_attack.json"
_mitre_cache: Optional[dict[str, Any]] = None


def _load_mitre() -> dict[str, Any]:
    """Load enterprise_attack.json once and cache it."""
    global _mitre_cache
    if _mitre_cache is not None:
        return _mitre_cache
    if not _MITRE_PATH.exists():
        # Return empty but valid structure if data isn't seeded
        _mitre_cache = {"version": "unseeded", "technique_count": 0, "techniques": {}}
        return _mitre_cache
    with open(_MITRE_PATH) as f:
        _mitre_cache = json.load(f)
    return _mitre_cache


# ════════════════════════════════════════════════════════════════════════════
# Single technique lookup  (public reference data)
# ════════════════════════════════════════════════════════════════════════════
@router.get("/technique/{technique_id}", response_model=TechniqueResponse)
async def get_technique(technique_id: str):
    """Get details for a specific MITRE ATT&CK technique."""
    data = _load_mitre()
    technique = data["techniques"].get(technique_id.upper())
    if technique is None:
        raise HTTPException(
            status_code=404,
            detail=f"Technique '{technique_id}' not found. "
                   f"Run `python scripts/seed_mitre.py` to download the matrix.",
        )
    return technique


# ════════════════════════════════════════════════════════════════════════════
# Matrix metadata  (public reference data)
# ════════════════════════════════════════════════════════════════════════════
@router.get("/matrix")
async def get_matrix_info():
    """Get info about the loaded ATT&CK matrix."""
    data = _load_mitre()
    return {
        "version": data.get("version"),
        "technique_count": data.get("technique_count", 0),
        "matrix": "enterprise",
    }


# ════════════════════════════════════════════════════════════════════════════
# Session coverage  (per-session data — auth + ownership required)
# ════════════════════════════════════════════════════════════════════════════
@router.get("/coverage/{session_id}", response_model=CoverageResponse)
async def get_session_coverage(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compute ATT&CK coverage for a session.

    "Used"     = techniques the attack engine actually executed
    "Detected" = techniques that produced at least one true-positive alert
    "Missed"   = used but never detected (the SOC's blind spots)
    """
    await verify_session_owner(db, session_id, current_user)

    # Get attack events to find techniques that were used
    attack_events = await crud.get_attack_events(db, session_id)
    used = {ev.technique_id for ev in attack_events if ev.technique_id}

    # Get alerts to find techniques that were detected
    alerts = await crud.get_alerts(db, session_id, limit=10_000)
    detected = {
        a.technique_id for a in alerts
        if a.technique_id and (a.is_true_positive is True or a.is_true_positive is None)
    }

    missed = used - detected
    coverage_pct = (len(detected & used) / len(used) * 100.0) if used else 0.0

    # By-tactic breakdown
    mitre_data = _load_mitre()
    techniques_db = mitre_data.get("techniques", {})
    by_tactic: dict[str, dict[str, int]] = defaultdict(lambda: {"used": 0, "detected": 0})

    for tid in used:
        info = techniques_db.get(tid, {})
        for tactic in info.get("tactics", ["unknown"]):
            by_tactic[tactic]["used"] += 1
    for tid in detected & used:
        info = techniques_db.get(tid, {})
        for tactic in info.get("tactics", ["unknown"]):
            by_tactic[tactic]["detected"] += 1

    return CoverageResponse(
        session_id=session_id,
        techniques_used=sorted(used),
        techniques_detected=sorted(detected & used),
        techniques_missed=sorted(missed),
        coverage_pct=round(coverage_pct, 1),
        by_tactic=dict(by_tactic),
    )
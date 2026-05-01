"""
Scenario endpoints — list available attack scenarios.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.schemas.scenario import ScenarioResponse, SCENARIO_REGISTRY

router = APIRouter()


@router.get("", response_model=list[ScenarioResponse])
async def list_scenarios():
    """Return all available attack scenarios."""
    return list(SCENARIO_REGISTRY.values())


@router.get("/{scenario_id}", response_model=ScenarioResponse)
async def get_scenario(scenario_id: str):
    """Get details for a specific scenario."""
    scenario = SCENARIO_REGISTRY.get(scenario_id)
    if scenario is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scenario '{scenario_id}' not found. "
                   f"Available: {list(SCENARIO_REGISTRY.keys())}",
        )
    return scenario

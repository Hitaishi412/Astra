"""
Detection rule endpoints — CRUD + validation.

Routes:
    GET    /detection/rules              — list all rules (optional ?session_id=...)
    POST   /detection/rules              — create a new rule
    POST   /detection/rules/validate     — validate YAML without saving
    GET    /detection/rules/{rule_id}    — get a single rule
    PATCH  /detection/rules/{rule_id}    — update a rule (enable/disable, edit YAML)
    DELETE /detection/rules/{rule_id}    — delete a user rule
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.schemas.detection import (
    RuleCreate,
    RuleUpdate,
    RuleResponse,
    RuleValidationResult,
)
from core.detection_engine.sigma_parser import parse_sigma_rule
from db import crud
from db.models import DetectionRule

router = APIRouter()


# ─── List ────────────────────────────────────────────────────────────────────
@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(
    session_id: str | None = None,
    enabled_only: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """List all detection rules. Defaults: returns globals + (optionally) session rules."""
    stmt = select(DetectionRule)
    if enabled_only:
        stmt = stmt.where(DetectionRule.enabled == True)
    if session_id:
        stmt = stmt.where(
            (DetectionRule.is_default == True) | (DetectionRule.session_id == session_id)
        )
    else:
        stmt = stmt.where(DetectionRule.is_default == True)
    stmt = stmt.order_by(DetectionRule.created_at.desc())

    result = await db.execute(stmt)
    return list(result.scalars().all())


# ─── Validate ────────────────────────────────────────────────────────────────
@router.post("/rules/validate", response_model=RuleValidationResult)
async def validate_rule(body: RuleCreate):
    """Validate a Sigma YAML rule without saving it. Useful for the rule editor UI."""
    try:
        parsed = parse_sigma_rule(body.rule_yaml)
        return RuleValidationResult(
            valid=True,
            rule_id=parsed.id,
            rule_name=parsed.name,
            parsed={
                "name": parsed.name,
                "severity": parsed.severity,
                "selections": list(parsed.selections.keys()),
                "condition": parsed.condition,
                "technique_id": parsed.technique_id,
                "tactic": parsed.tactic,
                "timeframe_seconds": parsed.timeframe_seconds,
                "has_aggregation": parsed.aggregation is not None,
            },
        )
    except Exception as e:
        return RuleValidationResult(valid=False, error=str(e))


# ─── Create ──────────────────────────────────────────────────────────────────
@router.post("/rules", response_model=RuleResponse, status_code=201)
async def create_rule(body: RuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new user detection rule. Validates the YAML before saving."""
    # Validate first
    try:
        parse_sigma_rule(body.rule_yaml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Sigma YAML: {e}")

    rule = await crud.create_detection_rule(
        db,
        name=body.name,
        description=body.description,
        severity=body.severity,
        rule_yaml=body.rule_yaml,
        session_id=body.session_id,
        is_default=False,
        enabled=True,
    )
    return rule


# ─── Get one ─────────────────────────────────────────────────────────────────
@router.get("/rules/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


# ─── Update ──────────────────────────────────────────────────────────────────
@router.patch("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a rule. Cannot edit default rules' YAML, but you can disable them."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    updates = body.model_dump(exclude_unset=True)

    if "rule_yaml" in updates:
        if rule.is_default:
            raise HTTPException(
                status_code=400,
                detail="Cannot modify the YAML of a default rule. You can disable it or copy it to a new rule.",
            )
        try:
            parse_sigma_rule(updates["rule_yaml"])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid Sigma YAML: {e}")

    for k, v in updates.items():
        setattr(rule, k, v)
    await db.flush()
    return rule


# ─── Delete ──────────────────────────────────────────────────────────────────
@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if rule.is_default:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a default rule. Disable it instead.",
        )
    await db.delete(rule)
    await db.flush()
    return None

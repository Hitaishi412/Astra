"""
Detection rule endpoints — CRUD + validation.

Routes:
    GET    /detection/rules              — list rules (globals + your session's, with ?session_id=...)
    POST   /detection/rules              — create a new rule (must name a session you own)
    POST   /detection/rules/validate     — validate YAML without saving
    GET    /detection/rules/{rule_id}    — get a single rule
    PATCH  /detection/rules/{rule_id}    — update a rule (your rules only)
    DELETE /detection/rules/{rule_id}    — delete a user rule (your rules only)

Auth: every endpoint requires a valid token. Default (is_default) rules are
global — readable by all, but NOT editable/deletable/toggleable by an individual
user. Non-default rules are scoped to the session that created them.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from api.ownership import verify_rule_owner, verify_session_owner
from api.schemas.detection import (
    RuleCreate,
    RuleUpdate,
    RuleResponse,
    RuleValidationResult,
)
from core.detection_engine.sigma_parser import parse_sigma_rule
from db import crud
from db.models import DetectionRule, User

router = APIRouter()


# ─── List ────────────────────────────────────────────────────────────────────
@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(
    session_id: str | None = None,
    enabled_only: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List detection rules: globals always, plus your session's rules if you
    pass a session_id you own."""
    if session_id:
        await verify_session_owner(db, session_id, current_user)

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
async def validate_rule(
    body: RuleCreate,
    current_user: User = Depends(get_current_user),
):
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
async def create_rule(
    body: RuleCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user detection rule. Must be attached to a session you own."""
    # Rules are session-scoped and owned — no orphan/global rules from users.
    if not body.session_id:
        raise HTTPException(
            status_code=400,
            detail="session_id is required — rules are scoped to a session you own.",
        )
    await verify_session_owner(db, body.session_id, current_user)

    # Validate the YAML
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
async def get_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Globals are readable by all; user rules only by their owner.
    return await verify_rule_owner(db, rule_id, current_user)


# ─── Update ──────────────────────────────────────────────────────────────────
@router.patch("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update one of your own rules. Default (global) rules can't be modified."""
    rule = await verify_rule_owner(db, rule_id, current_user)

    if rule.is_default:
        # Global rule — not an individual user's to change (incl. enable/disable).
        raise HTTPException(
            status_code=400,
            detail="Default rules are global and can't be modified. "
                   "Copy it to a new rule instead.",
        )

    updates = body.model_dump(exclude_unset=True)

    if "rule_yaml" in updates:
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
async def delete_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete one of your own rules. Default (global) rules can't be deleted."""
    rule = await verify_rule_owner(db, rule_id, current_user)

    if rule.is_default:
        raise HTTPException(
            status_code=400,
            detail="Default rules are global and can't be deleted.",
        )

    await db.delete(rule)
    await db.flush()
    return None
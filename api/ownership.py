"""
api/ownership.py
─────────────────
Shared object-ownership checks used across routers.

Why this exists:
  The app connects to Postgres through a pooled, privileged role, so
  Row-Level Security almost certainly isn't enforced on these queries.
  Per-user isolation therefore depends entirely on the application
  verifying that the object a request names actually belongs to the
  authenticated user. These helpers centralise that check so every
  router does it identically.

Convention:
  Every helper raises 404 (not 403) on "not found" OR "not yours", so we
  never reveal to a non-owner that an id exists.
"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db import crud
from db.models import Alert, DetectionRule, Session as SessionModel, User


async def verify_session_owner(db: AsyncSession, session_id: str, user: User) -> SessionModel:
    """Return the session iff it exists and belongs to `user`, else 404."""
    session = await crud.get_session(db, session_id)
    if session is None or session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


async def verify_alert_owner(db: AsyncSession, alert_id: str, user: User) -> Alert:
    """Return the alert iff it exists and its session belongs to `user`, else 404.

    Alerts have no direct user_id — they belong to a session, which has the
    owner — so we resolve Alert -> Session -> owner.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    session = await crud.get_session(db, alert.session_id)
    if session is None or session.user_id != user.id:
        # Same 404 + message as "not found" so we don't reveal the id exists.
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


async def verify_rule_owner(db: AsyncSession, rule_id: str, user: User) -> DetectionRule:
    """Return the rule iff the caller may read it, else 404.

    Default (global) rules are readable by everyone. Non-default rules belong
    to the session that created them, so we check that the rule's session is
    owned by `user`.

    NOTE: this governs READ access only. Callers that MUTATE a rule must
    additionally refuse `is_default` rules themselves — a global rule must not
    be editable/deletable/toggleable by an individual user.
    """
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule.is_default:
        return rule  # global, readable by all

    session = await crud.get_session(db, rule.session_id) if rule.session_id else None
    if session is None or session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule
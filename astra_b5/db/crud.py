"""
Reusable database queries — thin wrappers around SQLAlchemy for common operations.
Every function takes an AsyncSession and returns model instances or data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import User, Session, AttackEvent, LogEntry, Alert, DetectionRule, Report, Score


# ===========================================================================
# USER
# ===========================================================================
async def create_user(db: AsyncSession, username: str, display_name: str | None = None) -> User:
    user = User(username=username, display_name=display_name or username)
    db.add(user)
    await db.flush()
    return user


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_or_create_user(db: AsyncSession, username: str) -> User:
    user = await get_user_by_username(db, username)
    if user is None:
        user = await create_user(db, username)
    return user


# ===========================================================================
# SESSION
# ===========================================================================
async def create_session(
    db: AsyncSession,
    user_id: str,
    scenario_id: str,
    role: str,
    difficulty: str = "medium",
) -> Session:
    session = Session(
        user_id=user_id,
        scenario_id=scenario_id,
        role=role,
        difficulty=difficulty,
        status="created",
    )
    db.add(session)
    await db.flush()
    return session


async def get_session(db: AsyncSession, session_id: str) -> Session | None:
    result = await db.execute(select(Session).where(Session.id == session_id))
    return result.scalar_one_or_none()


async def update_session_status(db: AsyncSession, session_id: str, status: str) -> None:
    values = {"status": status}
    if status == "running":
        values["started_at"] = datetime.now(timezone.utc)
    elif status in ("completed", "aborted"):
        values["ended_at"] = datetime.now(timezone.utc)
    await db.execute(update(Session).where(Session.id == session_id).values(**values))


async def list_sessions(db: AsyncSession, user_id: str | None = None, limit: int = 20) -> list[Session]:
    stmt = select(Session).order_by(Session.created_at.desc()).limit(limit)
    if user_id:
        stmt = stmt.where(Session.user_id == user_id)
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ===========================================================================
# ATTACK EVENTS
# ===========================================================================
async def create_attack_event(db: AsyncSession, **kwargs) -> AttackEvent:
    event = AttackEvent(**kwargs)
    db.add(event)
    await db.flush()
    return event


async def get_attack_events(db: AsyncSession, session_id: str) -> list[AttackEvent]:
    result = await db.execute(
        select(AttackEvent)
        .where(AttackEvent.session_id == session_id)
        .order_by(AttackEvent.step_number)
    )
    return list(result.scalars().all())


# ===========================================================================
# LOG ENTRIES
# ===========================================================================
async def create_log_entry(db: AsyncSession, **kwargs) -> LogEntry:
    entry = LogEntry(**kwargs)
    db.add(entry)
    await db.flush()
    return entry


async def bulk_create_log_entries(db: AsyncSession, entries: list[dict]) -> int:
    objects = [LogEntry(**e) for e in entries]
    db.add_all(objects)
    await db.flush()
    return len(objects)


async def get_logs(
    db: AsyncSession,
    session_id: str,
    source: str | None = None,
    is_malicious: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[LogEntry]:
    stmt = select(LogEntry).where(LogEntry.session_id == session_id)
    if source:
        stmt = stmt.where(LogEntry.source == source)
    if is_malicious is not None:
        stmt = stmt.where(LogEntry.is_malicious == is_malicious)
    stmt = stmt.order_by(LogEntry.timestamp.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ===========================================================================
# ALERTS
# ===========================================================================
async def create_alert(db: AsyncSession, **kwargs) -> Alert:
    alert = Alert(**kwargs)
    db.add(alert)
    await db.flush()
    return alert


async def get_alerts(
    db: AsyncSession,
    session_id: str,
    severity: str | None = None,
    triage_status: str | None = None,
    limit: int = 100,
) -> list[Alert]:
    stmt = select(Alert).where(Alert.session_id == session_id)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if triage_status:
        stmt = stmt.where(Alert.triage_status == triage_status)
    stmt = stmt.order_by(Alert.timestamp.desc()).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def triage_alert(
    db: AsyncSession,
    alert_id: str,
    triage_status: str,
    analyst_notes: str | None = None,
    is_true_positive: bool | None = None,
) -> None:
    values = {
        "triage_status": triage_status,
        "triaged_at": datetime.now(timezone.utc),
    }
    if analyst_notes is not None:
        values["analyst_notes"] = analyst_notes
    if is_true_positive is not None:
        values["is_true_positive"] = is_true_positive
    await db.execute(update(Alert).where(Alert.id == alert_id).values(**values))


# ===========================================================================
# DETECTION RULES
# ===========================================================================
async def create_detection_rule(db: AsyncSession, **kwargs) -> DetectionRule:
    rule = DetectionRule(**kwargs)
    db.add(rule)
    await db.flush()
    return rule


async def get_active_rules(db: AsyncSession, session_id: str | None = None) -> list[DetectionRule]:
    stmt = select(DetectionRule).where(DetectionRule.enabled == True)
    if session_id:
        stmt = stmt.where(
            (DetectionRule.is_default == True) | (DetectionRule.session_id == session_id)
        )
    else:
        stmt = stmt.where(DetectionRule.is_default == True)
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ===========================================================================
# REPORTS
# ===========================================================================
async def create_report(db: AsyncSession, **kwargs) -> Report:
    report = Report(**kwargs)
    db.add(report)
    await db.flush()
    return report


async def get_report(db: AsyncSession, report_id: str) -> Report | None:
    result = await db.execute(select(Report).where(Report.id == report_id))
    return result.scalar_one_or_none()


async def update_report(db: AsyncSession, report_id: str, **kwargs) -> None:
    kwargs["updated_at"] = datetime.now(timezone.utc)
    await db.execute(update(Report).where(Report.id == report_id).values(**kwargs))


# ===========================================================================
# SCORES
# ===========================================================================
async def create_score(db: AsyncSession, **kwargs) -> Score:
    score = Score(**kwargs)
    db.add(score)
    await db.flush()
    return score


async def get_score(db: AsyncSession, session_id: str) -> Score | None:
    result = await db.execute(select(Score).where(Score.session_id == session_id))
    return result.scalar_one_or_none()


async def get_leaderboard(db: AsyncSession, limit: int = 20) -> list[Score]:
    result = await db.execute(
        select(Score).order_by(Score.total_score.desc()).limit(limit)
    )
    return list(result.scalars().all())

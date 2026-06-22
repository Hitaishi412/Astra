"""
api/routers/reports.py
───────────────────────
Reports API.

Endpoints:
    GET  /reports/templates/{mode}              — templates available for a mode (public reference)
    GET  /reports/{session_id}/facts            — ground truth facts for the side panel
    GET  /reports/{session_id}                  — list reports submitted for a session
    GET  /reports/{session_id}/{report_type}    — fetch a specific report (draft or submitted)
    POST /reports/{session_id}/draft            — autosave a draft
    POST /reports/{session_id}/submit           — final submission, runs evaluator

Auth: every session-scoped endpoint requires a valid token and verifies the
session belongs to the caller (404, not 403, otherwise). Only /templates/{mode}
is unauthenticated — it returns static report structure, no user data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from api.firebase_auth import get_current_user
from api.ownership import verify_session_owner
from api.schemas.report import (
    DimensionFeedback,
    DraftIn,
    DraftOut,
    ReportOut,
    ReportScoreOut,
    ReportTemplateOut,
    SectionTemplate,
    SessionFactsOut,
    SubmissionResultOut,
)
from core.reports.evaluator import evaluate_report
from core.reports.session_facts import collect_session_facts
from core.reports.templates import (
    INCIDENT_REPORT,
    PENTEST_REPORT,
    get_template,
    templates_for_mode,
)
from db.models import Report, Score, Session as SessionModel, User

logger = logging.getLogger("astra.api.reports")
router = APIRouter()


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════
def _template_to_schema(t) -> ReportTemplateOut:
    return ReportTemplateOut(
        id=t.id,
        name=t.name,
        description=t.description,
        audience=t.audience,
        sections=[
            SectionTemplate(
                id=s.id,
                title=s.title,
                prompt=s.prompt,
                placeholder=s.placeholder,
                required=s.required,
                min_words=s.min_words,
            )
            for s in t.sections
        ],
    )


# ════════════════════════════════════════════════════════════════════════════
# GET /reports/templates/{mode}   — public static reference (no user data)
# ════════════════════════════════════════════════════════════════════════════
@router.get("/templates/{mode}", response_model=list[ReportTemplateOut])
async def get_templates_for_mode(mode: str):
    """Return the list of report templates the given mode should write."""
    if mode not in {"soc", "pentester", "purple"}:
        raise HTTPException(status_code=400, detail=f"Unknown mode: {mode}")
    return [_template_to_schema(t) for t in templates_for_mode(mode)]


# ════════════════════════════════════════════════════════════════════════════
# GET /reports/{session_id}/facts
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{session_id}/facts", response_model=SessionFactsOut)
async def get_session_facts(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get ground-truth facts about a session for the side panel."""
    await verify_session_owner(db, session_id, current_user)

    facts = await collect_session_facts(session_id, db)
    if facts is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionFactsOut(
        session_id=facts.session_id,
        scenario=facts.scenario,
        mode=facts.mode,
        techniques_used=sorted(facts.techniques_used),
        techniques_detected=sorted(facts.techniques_detected),
        techniques_missed=sorted(facts.techniques_missed),
        tactics_reached=sorted(facts.tactics_reached),
        hostnames=sorted(facts.hostnames),
        ip_addresses=sorted(facts.ip_addresses),
        usernames=sorted(facts.usernames),
        processes=sorted(facts.processes),
        total_alerts=facts.total_alerts,
        total_attack_steps=facts.total_attack_steps,
        coverage_pct=facts.coverage_pct,
        mttd_sec=facts.mttd_sec,
        duration_sec=facts.duration_sec,
    )


# ════════════════════════════════════════════════════════════════════════════
# GET /reports/{session_id}              — list reports for a session
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{session_id}", response_model=list[ReportOut])
async def list_reports_for_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all reports (drafts and submissions) for a session."""
    await verify_session_owner(db, session_id, current_user)

    result = await db.execute(
        select(Report).where(Report.session_id == session_id)
    )
    reports = result.scalars().all()
    return [_report_to_out(r) for r in reports]


# ════════════════════════════════════════════════════════════════════════════
# GET /reports/{session_id}/{report_type}    — fetch a specific report
# ════════════════════════════════════════════════════════════════════════════
@router.get("/{session_id}/{report_type}", response_model=ReportOut)
async def get_report(
    session_id: str,
    report_type: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a specific report for a session."""
    if report_type not in {"incident", "pentest"}:
        raise HTTPException(status_code=400, detail=f"Unknown report_type: {report_type}")

    await verify_session_owner(db, session_id, current_user)

    result = await db.execute(
        select(Report)
        .where(Report.session_id == session_id)
        .where(Report.report_type == report_type)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="No report found")
    return _report_to_out(report)


# ════════════════════════════════════════════════════════════════════════════
# POST /reports/{session_id}/draft   — autosave
# ════════════════════════════════════════════════════════════════════════════
@router.post("/{session_id}/draft", response_model=DraftOut)
async def save_draft(
    session_id: str,
    body: DraftIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Save (or autosave) a draft of the report."""
    if body.report_type not in {"incident", "pentest"}:
        raise HTTPException(status_code=400, detail=f"Unknown report_type: {body.report_type}")

    session = await verify_session_owner(db, session_id, current_user)

    # Look for existing report of this type
    existing_q = await db.execute(
        select(Report)
        .where(Report.session_id == session_id)
        .where(Report.report_type == body.report_type)
    )
    report = existing_q.scalar_one_or_none()

    title = body.title or _default_title(body.report_type, session.scenario_id)
    now = datetime.now(timezone.utc)

    if report is None:
        report = Report(
            session_id=session_id,
            user_id=session.user_id,
            report_type=body.report_type,
            title=title,
            sections=body.content,
            findings=[],
        )
        db.add(report)
    else:
        # Don't allow editing once submitted
        if report.quality_score is not None:
            raise HTTPException(
                status_code=409,
                detail="Report already submitted; cannot edit a submitted report",
            )
        report.sections = body.content
        report.title = title
        report.updated_at = now

    await db.commit()
    await db.refresh(report)

    return DraftOut(
        report_id=report.id,
        session_id=report.session_id,
        report_type=report.report_type,
        content=report.sections or {},
        submitted=report.quality_score is not None,
        updated_at=report.updated_at,
    )


# ════════════════════════════════════════════════════════════════════════════
# POST /reports/{session_id}/submit  — final submission, runs evaluator
# ════════════════════════════════════════════════════════════════════════════
@router.post("/{session_id}/submit", response_model=SubmissionResultOut)
async def submit_report(
    session_id: str,
    body: DraftIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit the report — runs the evaluator and persists the score."""
    if body.report_type not in {"incident", "pentest"}:
        raise HTTPException(status_code=400, detail=f"Unknown report_type: {body.report_type}")

    template = get_template(body.report_type)
    if template is None:
        raise HTTPException(status_code=400, detail="Template not found")

    session = await verify_session_owner(db, session_id, current_user)

    # Pull session facts
    facts = await collect_session_facts(session_id, db)
    if facts is None:
        raise HTTPException(status_code=404, detail="Session facts not available")

    # Run the evaluator
    score = evaluate_report(body.content, template, facts)

    # Convert dimensions to JSON-serializable shape
    feedback_payload = {
        "summary": score.summary_feedback,
        "dimensions": {
            name: {
                "score": dim.score,
                "weight": dim.weight,
                "feedback": dim.feedback,
                "matched": dim.matched,
                "missing": dim.missing,
            }
            for name, dim in score.dimensions.items()
        },
    }

    # Find or create the report row
    existing_q = await db.execute(
        select(Report)
        .where(Report.session_id == session_id)
        .where(Report.report_type == body.report_type)
    )
    report = existing_q.scalar_one_or_none()

    title = body.title or _default_title(body.report_type, session.scenario_id)
    now = datetime.now(timezone.utc)

    if report is None:
        report = Report(
            session_id=session_id,
            user_id=session.user_id,
            report_type=body.report_type,
            title=title,
            sections=body.content,
            quality_score=score.overall_score,
            feedback=feedback_payload,
            findings=[],
        )
        db.add(report)
    else:
        report.sections = body.content
        report.quality_score = score.overall_score
        report.feedback = feedback_payload
        report.updated_at = now

    await db.commit()
    await db.refresh(report)

    # Push the report quality into the session's Score row if present
    sc_q = await db.execute(select(Score).where(Score.session_id == session_id))
    sc = sc_q.scalar_one_or_none()
    if sc is not None:
        sc.report_quality_score = score.overall_score
        # Don't recompute total_score here — that's the session_finaliser's job.
        # But we update report quality so the live charts reflect it.
        await db.commit()

    return SubmissionResultOut(
        report_id=report.id,
        session_id=report.session_id,
        report_type=report.report_type,
        score=ReportScoreOut(
            overall_score=score.overall_score,
            grade=score.grade,
            dimensions={
                name: DimensionFeedback(
                    score=dim.score,
                    weight=dim.weight,
                    feedback=dim.feedback,
                    matched=dim.matched,
                    missing=dim.missing,
                )
                for name, dim in score.dimensions.items()
            },
            summary_feedback=score.summary_feedback,
        ),
        submitted_at=now,
    )


# ════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ════════════════════════════════════════════════════════════════════════════
def _default_title(report_type: str, scenario_id: str) -> str:
    return {
        "incident": f"Incident Response Report — {scenario_id}",
        "pentest":  f"Penetration Test Report — {scenario_id}",
    }.get(report_type, f"Report — {scenario_id}")


def _report_to_out(report: Report) -> ReportOut:
    feedback = report.feedback or {}
    grade = None
    if isinstance(feedback, dict):
        # Try to derive a grade from quality_score
        score = report.quality_score
        if score is not None:
            if score >= 85:   grade = "excellent"
            elif score >= 70: grade = "good"
            elif score >= 55: grade = "average"
            elif score >= 40: grade = "needs_improvement"
            else:             grade = "poor"

    return ReportOut(
        report_id=report.id,
        session_id=report.session_id,
        user_id=report.user_id,
        report_type=report.report_type,
        title=report.title,
        content=report.sections or {},
        submitted=report.quality_score is not None,
        overall_score=report.quality_score,
        grade=grade,
        feedback=report.feedback,
        created_at=report.created_at,
        updated_at=report.updated_at,
    )
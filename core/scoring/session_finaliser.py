"""
core/scoring/session_finaliser.py
──────────────────────────────────
Orchestrates everything that needs to happen when a session ends:

  1. Pull all attack events + alerts from DB
  2. Get coverage summary from the session's MitreMapper
  3. Run SessionScorer.compute()
  4. Persist the Score row to DB
  5. Publish a score update to the WebSocket channel

Called from:
  - api/routers/attacks.py  (when next_step() returns done=True)
  - api/routers/sessions.py (manual session completion endpoint)

Public interface
────────────────
    finaliser = SessionFinaliser(session_id, mapper)
    result    = await finaliser.finalise(db, report_quality_score=75.0)
    # result is a ScoreResult
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from core.mitre.mapper import MitreMapper
from core.scoring.calculator import SessionScorer, ScoreResult
from db import crud


class SessionFinaliser:
    """
    End-of-session orchestrator.

    One instance per session. Holds a reference to the session's MitreMapper
    so it can pull live coverage data without hitting the DB.
    """

    def __init__(self, session_id: str, mapper: MitreMapper) -> None:
        self.session_id = session_id
        self.mapper     = mapper
        self._scorer    = SessionScorer(session_id)

    async def finalise(
        self,
        db:                   AsyncSession,
        report_quality_score: float = 0.0,
    ) -> ScoreResult:
        """
        Run the full scoring pipeline and persist results.

        Steps:
          1. Load attack events from DB
          2. Load alerts from DB
          3. Get coverage from MitreMapper
          4. Compute score
          5. Upsert Score row
          6. Mark session completed

        Returns the ScoreResult for streaming to the dashboard.
        """
        # ── 1. Fetch raw data ─────────────────────────────────────────────────
        attack_events = await crud.get_attack_events(db, self.session_id)
        alerts        = await crud.get_alerts(db, self.session_id, limit=10_000)

        # ── 2. Session duration ───────────────────────────────────────────────
        session = await crud.get_session(db, self.session_id)
        duration_sec = 0.0
        if session and session.started_at:
            ended = getattr(session, "ended_at", None) or datetime.now(timezone.utc)
            # Handle naive/aware datetime comparison safely
            started = session.started_at
            if hasattr(started, "tzinfo") and started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            if hasattr(ended, "tzinfo") and ended.tzinfo is None:
                ended = ended.replace(tzinfo=timezone.utc)
            duration_sec = (ended - started).total_seconds()

        # ── 3. Coverage from live MitreMapper ─────────────────────────────────
        coverage = self.mapper.coverage_summary()

        # ── 4. Compute score ──────────────────────────────────────────────────
        result = self._scorer.compute(
            attack_events        = attack_events,
            alerts               = alerts,
            coverage             = coverage,
            report_quality_score = report_quality_score,
            session_duration_sec = duration_sec,
        )

        # ── 5. Persist Score row (upsert) ─────────────────────────────────────
        existing = await crud.get_score(db, self.session_id)
        if existing is None:
            await crud.create_score(db, **result.to_db_dict())
        else:
            # Update existing score (re-run scenario)
            from sqlalchemy import update as sa_update
            from db.models import Score
            await db.execute(
                sa_update(Score)
                .where(Score.session_id == self.session_id)
                .values(**{k: v for k, v in result.to_db_dict().items()
                           if k != "session_id"})
            )

        return result

    def live_preview(
        self,
        tp_count:    int,
        fp_count:    int,
        total_steps: int,
        mttd_sec:    float,
    ) -> dict:
        """
        Lightweight score estimate for the live dashboard ticker.
        Doesn't touch the DB — used only for streaming.
        """
        return self._scorer.quick_score(
            tp_count    = tp_count,
            fp_count    = fp_count,
            total_steps = total_steps,
            mttd_sec    = mttd_sec,
        )

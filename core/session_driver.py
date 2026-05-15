"""
core/session_driver.py
───────────────────────
The integration glue between every block.

Owns one full set of components per session:
  - AttackOrchestrator   (Block 2)
  - LogGenerator         (Block 3)
  - NoiseGenerator       (Block 3)
  - DetectionPipeline    (Block 4)
  - MitreMapper          (Block 5)
  - SessionFinaliser     (Block 9)

Drives the end-to-end flow when /attacks/run is called:

  for each AttackStep yielded by the orchestrator:
      1. persist AttackEvent (Block 1)
      2. mapper.record_step(step)               (Block 5)
      3. publish attack_status update           (Block 6)
      4. generate logs (attack + noise)         (Block 3)
      5. persist log entries                    (Block 1)
      6. publish each log                       (Block 6)
      7. feed logs to detection pipeline        (Block 4)
      8. persist alerts                         (Block 1)
      9. for each alert with technique_id:
          mapper.record_detection(alert)        (Block 5)
     10. publish alerts                          (Block 6)
     11. publish a quick score preview           (Block 6, Block 9)

  on completion:
      - run SessionFinaliser → persist Score    (Block 9)
      - publish final score                     (Block 6)
      - mark session "completed"
      - drop driver from registry

This is the *only* place that knows how all the blocks fit together.
The API endpoint just kicks off `SessionDriver.run()` as a background task.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from core.attack_engine.orchestrator import AttackOrchestrator
from core.attack_engine.techniques.base import AttackStep
from core.detection_engine.pipeline import DetectionPipeline
from core.log_engine.generator import LogGenerator
from core.log_engine.noise import NoiseGenerator
from core.log_engine.schemas import AlertSchema, LogEntry
from core.mitre.mapper import MitreMapper
from core.scoring.session_finaliser import SessionFinaliser
from db import crud
from db.engine import get_session
from streaming.publisher import (
    publish_alert,
    publish_attack_status,
    publish_log,
    publish_score,
)

logger = logging.getLogger("astra.session_driver")


# ════════════════════════════════════════════════════════════════════════════
# Per-session driver
# ════════════════════════════════════════════════════════════════════════════
class SessionDriver:
    """
    One driver per session. Owns the full per-session pipeline.

    Lifecycle:
        d = SessionDriver(session_id)
        await d.run(scenario_id="ransomware", difficulty="medium")

    The driver opens its own DB sessions internally (one per step) so the
    caller doesn't need to hold a long-running transaction. Designed to
    be invoked via asyncio.create_task() from a FastAPI endpoint that
    returns 202 Accepted immediately.
    """

    def __init__(
        self,
        session_id: str,
        anomaly_baseline_size: int = 50,   # Issue D: lower than default 200 — most demo sessions are short
    ) -> None:
        self.session_id = session_id
        self.orchestrator = AttackOrchestrator()
        self.log_gen = LogGenerator()
        self.noise_gen = NoiseGenerator()
        self.mapper = MitreMapper(session_id)
        self.pipeline = DetectionPipeline(
            session_id=session_id,
            anomaly_baseline_size=anomaly_baseline_size,
            enable_anomaly=True,
            enable_correlation=True,
        )
        self.finaliser = SessionFinaliser(session_id, self.mapper)

        # Counters for the live score preview
        self._tp_count = 0
        self._fp_count = 0
        self._step_count = 0

        # State flags
        self._aborted = False
        self._completed = False

    # ── Initialization ──────────────────────────────────────────────────────
    async def initialize(self, db: AsyncSession) -> dict:
        """Load detection rules from disk + DB. Call once before run()."""
        return await self.pipeline.initialize(db, load_disk_defaults=True)

    # ── Abort (called from API) ─────────────────────────────────────────────
    def abort(self) -> None:
        self._aborted = True
        try:
            self.orchestrator.abort()
        except Exception:
            pass

    @property
    def is_running(self) -> bool:
        return not (self._aborted or self._completed)

    # ── Main driver ─────────────────────────────────────────────────────────
    async def run(
        self,
        scenario_id: str,
        difficulty: str = "medium",
        target_ip: Optional[str] = None,
        step_delay_ms: int = 800,
    ) -> dict:
        """
        Execute the full session: attack steps → logs → detections → score.

        Designed to be run as a background task (asyncio.create_task).
        Opens its own DB sessions; does not require an outer transaction.
        Bug B: every exit path drops the driver from the registry via finally.
        """
        # Initialize detection rules using a short-lived session
        try:
            async with get_session() as db:
                await self.initialize(db)
        except Exception as e:
            logger.exception(f"[driver] init failed for session={self.session_id}: {e}")
            await self._publish_status("failed", phase=None, error=str(e))
            drop_driver(self.session_id)
            return {"status": "failed", "error": str(e)}

        await self._publish_status("starting", phase=None)

        try:
            try:
                async for step in self.orchestrator.run_scenario_async(
                    scenario_id=scenario_id,
                    difficulty=difficulty,
                    target_ip=target_ip,
                    step_delay_ms=step_delay_ms,
                ):
                    if self._aborted:
                        break
                    # Each step gets its own committed transaction so events
                    # are immediately visible to other readers (the dashboard
                    # polling endpoints, for instance).
                    try:
                        async with get_session() as db:
                            await self._handle_step(db, step)
                    except Exception as e:
                        logger.exception(f"[driver] step {step.step_number} failed: {e}")
                        # Keep going — one bad step shouldn't abort the run
            except asyncio.CancelledError:
                logger.info(f"[driver] session {self.session_id} cancelled")
                self._aborted = True
                raise

            # Finalise — compute and persist score, publish it
            try:
                async with get_session() as db:
                    if self._aborted:
                        await crud.update_session_status(db, self.session_id, "aborted")
                        score_result = None
                    else:
                        await crud.update_session_status(db, self.session_id, "completed")
                        score_result = await self.finaliser.finalise(db, report_quality_score=0.0)
                        self._completed = True

                # Publish AFTER the DB session commits
                if score_result is not None:
                    await publish_score(self.session_id, score_result.to_db_dict())
                    await self._publish_status("completed", phase=None)
                else:
                    await self._publish_status("aborted", phase=None)
            except Exception as e:
                logger.exception(f"[driver] finalisation failed: {e}")
                await self._publish_status("failed", phase=None, error=str(e))

            return {
                "status": "aborted" if self._aborted else "completed",
                "session_id": self.session_id,
                "summary": self.mapper.coverage_summary(),
            }

        except asyncio.CancelledError:
            # Re-raise after cleanup happens in finally
            raise
        except Exception as e:
            logger.exception(f"[driver] session {self.session_id} crashed: {e}")
            await self._publish_status("failed", phase=None, error=str(e))
            return {"status": "failed", "error": str(e)}

        finally:
            # Bug B: registry cleanup happens on EVERY exit path
            drop_driver(self.session_id)

    # ════════════════════════════════════════════════════════════════════════
    # Per-step processing
    # ════════════════════════════════════════════════════════════════════════
    async def _handle_step(self, db: AsyncSession, step: AttackStep) -> None:
        """Process one AttackStep through the full pipeline."""
        self._step_count += 1

        # 1. Persist AttackEvent
        try:
            await crud.create_attack_event(db, **_step_to_db(step, self.session_id))
        except Exception as e:
            logger.exception(f"[driver] failed to persist attack event: {e}")

        # 2. Update MITRE mapper
        self.mapper.record_step(step)

        # 3. Publish attack status (kill chain progress)
        await self._publish_status(
            state="running",
            phase=step.phase,
            current_step=self._step_count,
            kill_chain=self.orchestrator.kill_chain_summary,
        )

        # 4. Generate logs (attack + interleaved noise)
        attack_logs = self.log_gen.generate(step, self.session_id)
        noise_count = max(1, getattr(step, "noise_count_hint", 5))
        noise_logs = self.noise_gen.burst(
            self.session_id,
            count=noise_count,
            base_time=step.timestamp,
        )
        # NoiseGenerator may or may not expose interleave(); fall back to concat
        if hasattr(self.noise_gen, "interleave"):
            all_logs = self.noise_gen.interleave(attack_logs, noise_logs)
        else:
            all_logs = list(attack_logs) + list(noise_logs)

        # 5. Persist logs in bulk — Bug A: ORM-friendly dicts (datetime, not str)
        if all_logs:
            try:
                await crud.bulk_create_log_entries(
                    db,
                    [_log_to_db_orm(log) for log in all_logs],
                )
            except Exception as e:
                logger.exception(f"[driver] failed to persist logs: {e}")

        # 6. Publish each log to streaming (use JSON-serialized form for transport)
        for log in all_logs:
            try:
                await publish_log(self.session_id, log.to_db_dict())
            except Exception as e:
                logger.debug(f"[driver] publish_log failed: {e}")

        # 7. Detection pipeline
        try:
            new_alerts = self.pipeline.process_logs(all_logs)
        except Exception as e:
            logger.exception(f"[driver] detection pipeline crashed: {e}")
            new_alerts = []

        # 8/9/10. Persist alerts, update mapper, publish
        for alert in new_alerts:
            await self._handle_alert(db, alert)

        # 11. Publish a live score preview
        try:
            preview = self.finaliser.live_preview(
                tp_count=self._tp_count,
                fp_count=self._fp_count,
                total_steps=self._step_count,
                mttd_sec=self.mapper.coverage_summary().get("mean_dwell_time_sec", 0.0),
            )
            preview["session_id"] = self.session_id
            preview["preview"] = True
            await publish_score(self.session_id, preview)
        except Exception as e:
            logger.debug(f"[driver] score preview failed: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # Alert handling
    # ════════════════════════════════════════════════════════════════════════
    async def _handle_alert(self, db: AsyncSession, alert: AlertSchema) -> None:
        """Persist one alert, update mapper, publish to streaming."""
        # Update TP/FP counters for live preview
        if alert.is_true_positive is True:
            self._tp_count += 1
        elif alert.is_true_positive is False:
            self._fp_count += 1

        # Update MITRE mapper if we have a technique
        if alert.technique_id:
            try:
                self.mapper.record_detection(alert)
            except Exception as e:
                logger.debug(f"[driver] mapper.record_detection failed: {e}")

        # Persist to DB — Bug A: ORM-friendly dict, datetime stays native
        try:
            db_kwargs = _alert_to_db_orm(alert)
            await crud.create_alert(db, **db_kwargs)
        except Exception as e:
            logger.exception(f"[driver] failed to persist alert: {e}")

        # Publish (JSON-serialized for transport)
        try:
            await publish_alert(self.session_id, alert.to_db_dict())
        except Exception as e:
            logger.debug(f"[driver] publish_alert failed: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # Streaming helpers
    # ════════════════════════════════════════════════════════════════════════
    async def _publish_status(
        self,
        state: str,
        phase: Optional[str] = None,
        **extra: Any,
    ) -> None:
        """Publish kill-chain / session status."""
        kc = extra.pop("kill_chain", None) or self.orchestrator.kill_chain_summary or {}
        payload = {
            "session_id": self.session_id,
            "state": state,
            "current_phase": phase,
            "phases_completed": kc.get("phases_completed_list", []) if kc else [],
            "progress_pct": kc.get("progress_pct", 0) if kc else 0,
            "total_steps": kc.get("total_steps", 0) if kc else 0,
        }
        # Merge any extra fields the caller wants (current_step, error, etc.)
        for k, v in extra.items():
            if k not in payload:
                payload[k] = v
        try:
            await publish_attack_status(self.session_id, payload)
        except Exception as e:
            logger.debug(f"[driver] publish_attack_status failed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# Schema → DB-row converters (Bug A: keep datetime native)
# ════════════════════════════════════════════════════════════════════════════

def _step_to_db(step: AttackStep, session_id: str) -> dict:
    """Convert AttackStep into kwargs for crud.create_attack_event()."""
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
        "extra_data":     step.extra_data or {},
    }


# Alert DB columns (from db/models.py: Alert)
_ALERT_DB_COLUMNS = {
    "id", "session_id", "rule_id", "detection_type",
    "title", "description", "severity",
    "technique_id", "tactic",
    "source_ip", "destination_ip", "hostname", "username",
    "evidence", "triage_status", "is_true_positive",
    "timestamp",
}

# LogEntry DB columns (from db/models.py: LogEntry)
# Note: the schema has more fields than the DB model; extras go into raw_data.
_LOG_DB_COLUMNS = {
    "id", "session_id", "source", "event_id", "severity", "category",
    "message", "raw_data",
    "hostname", "source_ip", "destination_ip",
    "username", "process_name",
    "is_malicious", "attack_event_id", "timestamp",
}


def _alert_to_db_orm(alert: AlertSchema) -> dict:
    """
    Convert AlertSchema to kwargs for crud.create_alert().

    Uses model_dump() WITHOUT mode='json' so datetime stays native.
    """
    raw = alert.model_dump()
    return {k: v for k, v in raw.items() if k in _ALERT_DB_COLUMNS}


def _log_to_db_orm(log: LogEntry) -> dict:
    """
    Convert LogEntry to kwargs for crud.bulk_create_log_entries.

    Critically:
      - Uses model_dump() (not mode='json') so datetime stays native
        (Bug A — SQLAlchemy DateTime column won't coerce ISO strings)
      - Filters out fields the DB model doesn't have (source_port,
        destination_port, process_id, parent_process, file_path,
        command_line) and folds them into raw_data instead, so the
        information isn't lost.
    """
    raw = log.model_dump()
    extras_for_raw = {}
    for k in ("source_port", "destination_port", "process_id",
              "parent_process", "file_path", "command_line"):
        v = raw.pop(k, None)
        if v is not None:
            extras_for_raw[k] = v

    # Merge extras into raw_data
    raw_data = raw.get("raw_data") or {}
    if extras_for_raw:
        raw_data = {**raw_data, **extras_for_raw}
    raw["raw_data"] = raw_data

    return {k: v for k, v in raw.items() if k in _LOG_DB_COLUMNS}


# ════════════════════════════════════════════════════════════════════════════
# Per-process registry of active drivers
# ════════════════════════════════════════════════════════════════════════════

_drivers: dict[str, SessionDriver] = {}
_driver_tasks: dict[str, asyncio.Task] = {}
_drivers_lock = threading.Lock()


def get_driver(session_id: str) -> Optional[SessionDriver]:
    with _drivers_lock:
        return _drivers.get(session_id)


def register_driver(session_id: str, driver: SessionDriver) -> None:
    with _drivers_lock:
        _drivers[session_id] = driver


def register_task(session_id: str, task: asyncio.Task) -> None:
    with _drivers_lock:
        _driver_tasks[session_id] = task


def get_task(session_id: str) -> Optional[asyncio.Task]:
    with _drivers_lock:
        return _driver_tasks.get(session_id)


def drop_driver(session_id: str) -> None:
    with _drivers_lock:
        _drivers.pop(session_id, None)
        _driver_tasks.pop(session_id, None)


def list_active_sessions() -> list[str]:
    with _drivers_lock:
        return list(_drivers.keys())

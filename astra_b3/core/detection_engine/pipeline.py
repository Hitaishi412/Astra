"""
core/detection_engine/pipeline.py
──────────────────────────────────
The main detection pipeline.

Public interface:
─────────────────
    pipeline = DetectionPipeline(session_id="...")
    await pipeline.initialize(db_session)

    # Process a batch of logs
    alerts = pipeline.process_logs(batch_of_logs)

    # Process a single log (for streaming use)
    alerts = pipeline.process_log(single_log)

The pipeline runs each log through:
    1. Sigma rule evaluation (real-time match)
    2. Anomaly detection (after baseline is trained)
    3. Correlation engine (combines lower alerts into incidents)

Returns a flat list of AlertSchema objects per call.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from core.log_engine.schemas import LogEntry, AlertSchema
from core.detection_engine.alert import build_sigma_alert, build_anomaly_alert
from core.detection_engine.anomaly_detector import AnomalyDetector
from core.detection_engine.correlation import CorrelationEngine
from core.detection_engine.rule_manager import RuleManager
from core.detection_engine.sigma_parser import evaluate_rule


class DetectionPipeline:
    """
    The orchestrator that ties Sigma + Anomaly + Correlation together.

    One instance per active training session.
    """

    def __init__(
        self,
        session_id: str,
        anomaly_baseline_size: int = 200,
        anomaly_contamination: float = 0.05,
        anomaly_threshold: float = -0.10,
        enable_anomaly: bool = True,
        enable_correlation: bool = True,
    ):
        self.session_id = session_id
        self.rule_manager = RuleManager()
        self.anomaly_detector = AnomalyDetector(
            contamination=anomaly_contamination,
            baseline_size=anomaly_baseline_size,
            anomaly_threshold=anomaly_threshold,
        ) if enable_anomaly else None
        self.correlator = CorrelationEngine() if enable_correlation else None

        # Pending logs accumulate for window-based Sigma rules
        self._log_buffer: list[LogEntry] = []
        self._max_buffer_size = 5000   # safety cap

        # Stats
        self._logs_processed = 0
        self._alerts_emitted = 0

    # ════════════════════════════════════════════════════════════════════════
    # INITIALIZATION
    # ════════════════════════════════════════════════════════════════════════
    async def initialize(
        self,
        db: Optional[AsyncSession] = None,
        load_disk_defaults: bool = True,
    ) -> dict:
        """
        Load all rules. Call once after instantiation.
        Returns load stats.
        """
        disk_count = 0
        db_count = 0

        if load_disk_defaults:
            disk_count = self.rule_manager.load_defaults_from_disk()

        if db is not None:
            db_count = await self.rule_manager.load_user_rules_from_db(
                db, session_id=self.session_id
            )

        return {
            "disk_rules_loaded": disk_count,
            "db_rules_loaded": db_count,
            **self.rule_manager.stats,
        }

    # ════════════════════════════════════════════════════════════════════════
    # PROCESSING
    # ════════════════════════════════════════════════════════════════════════
    def process_log(self, log: LogEntry) -> list[AlertSchema]:
        """Process a single log through all detectors."""
        return self.process_logs([log])

    def process_logs(self, logs: list[LogEntry]) -> list[AlertSchema]:
        """
        Process a batch of logs through Sigma → Anomaly → Correlation.

        Returns all alerts generated during this call.
        """
        if not logs:
            return []

        self._logs_processed += len(logs)
        alerts: list[AlertSchema] = []

        # ── Stage 1: Sigma rule evaluation ──────────────────────────────────
        # Add to buffer (for time-window aggregation rules)
        self._log_buffer.extend(logs)
        if len(self._log_buffer) > self._max_buffer_size:
            self._log_buffer = self._log_buffer[-self._max_buffer_size:]

        sigma_alerts = self._run_sigma(self._log_buffer, only_new=logs)
        alerts.extend(sigma_alerts)

        # ── Stage 2: Anomaly detection ──────────────────────────────────────
        if self.anomaly_detector:
            anomaly_alerts = self._run_anomaly(logs)
            alerts.extend(anomaly_alerts)

        # ── Stage 3: Correlation ────────────────────────────────────────────
        if self.correlator and alerts:
            for alert in alerts:
                self.correlator.add_alert(alert)
            correlation_alerts = self.correlator.find_correlations(self.session_id)
            alerts.extend(correlation_alerts)

        self._alerts_emitted += len(alerts)
        return alerts

    # ════════════════════════════════════════════════════════════════════════
    # SIGMA STAGE
    # ════════════════════════════════════════════════════════════════════════
    def _run_sigma(
        self,
        all_logs: list[LogEntry],
        only_new: list[LogEntry],
    ) -> list[AlertSchema]:
        """
        Run every active Sigma rule against the log buffer.
        Only emit alerts whose evidence includes at least one of the new logs
        (to avoid re-emitting an old match on every batch).
        """
        new_log_ids = {log.id for log in only_new}
        alerts = []

        for rule in self.rule_manager.active_rules():
            try:
                matches = evaluate_rule(rule, all_logs)
            except Exception as e:
                print(f"[PIPELINE] Rule {rule.name} failed: {e}")
                continue

            for matched_logs in matches:
                # Only emit if at least one of the matched logs is new
                if not any(log.id in new_log_ids for log in matched_logs):
                    continue

                rule_dict = {
                    "id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "technique_id": rule.technique_id,
                    "tactic": rule.tactic,
                }
                alert = build_sigma_alert(
                    session_id=self.session_id,
                    rule=rule_dict,
                    matched_logs=matched_logs,
                )
                # Mark TP if any of the matched logs were truly malicious
                alert.is_true_positive = any(log.is_malicious for log in matched_logs)
                alerts.append(alert)

        return alerts

    # ════════════════════════════════════════════════════════════════════════
    # ANOMALY STAGE
    # ════════════════════════════════════════════════════════════════════════
    def _run_anomaly(self, logs: list[LogEntry]) -> list[AlertSchema]:
        """Add to baseline, then score post-fit logs."""
        alerts = []
        for log in logs:
            if not self.anomaly_detector.is_fitted:
                full = self.anomaly_detector.add_for_baseline(log)
                if full:
                    self.anomaly_detector.fit_baseline()
                continue

            score = self.anomaly_detector.score(log)
            if score < self.anomaly_detector.anomaly_threshold:
                explanation = self.anomaly_detector.explain(log)
                alert = build_anomaly_alert(
                    session_id=self.session_id,
                    anomaly_score=score,
                    feature_summary=explanation,
                    triggering_logs=[log],
                    severity=_severity_from_score(score),
                )
                alert.is_true_positive = log.is_malicious
                alerts.append(alert)
        return alerts

    # ════════════════════════════════════════════════════════════════════════
    # STATS
    # ════════════════════════════════════════════════════════════════════════
    @property
    def stats(self) -> dict:
        return {
            "session_id": self.session_id,
            "logs_processed": self._logs_processed,
            "alerts_emitted": self._alerts_emitted,
            "buffer_size": len(self._log_buffer),
            "anomaly_fitted": self.anomaly_detector.is_fitted if self.anomaly_detector else False,
            "anomaly_baseline_progress": (
                self.anomaly_detector.baseline_progress if self.anomaly_detector else 0.0
            ),
            **self.rule_manager.stats,
        }


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _severity_from_score(score: float) -> str:
    """Map an anomaly score to a severity label."""
    if score < -0.30:
        return "critical"
    if score < -0.20:
        return "high"
    if score < -0.10:
        return "medium"
    return "low"

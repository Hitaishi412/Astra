"""
core/mitre/mapper.py
─────────────────────
Per-session MITRE ATT&CK coverage tracker.

One MitreMapper instance lives for the lifetime of a training session.
The attack engine calls record_step() after every AttackStep.
The detection engine calls record_detection() after every true-positive alert.
The scoring engine reads the coverage summary at session end.

Public interface
────────────────
    mapper = MitreMapper(session_id="abc-123")

    # Block 2 hook — called in api/routers/attacks.py after each step
    mapper.record_step(step)

    # Block 4 hook — called in api/routers/attacks.py after alert evaluation
    mapper.record_detection(alert)

    # Scoring / dashboard read
    summary = mapper.coverage_summary()
    matrix  = mapper.matrix_view()
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from core.attack_engine.techniques.base import AttackStep
from core.log_engine.schemas import AlertSchema
from core.mitre.technique_store import technique_store


# ─── Internal records ─────────────────────────────────────────────────────────

@dataclass
class TechniqueRecord:
    """Everything we know about one technique within a session."""
    technique_id:   str
    technique_name: str
    tactic:         str
    phase:          str

    # Execution tracking
    executions:          int = 0
    successful_executions: int = 0
    first_seen:          Optional[datetime] = None
    last_seen:           Optional[datetime] = None

    # Detection tracking
    detections:          int = 0           # alerts that fired for this technique
    first_detected_at:   Optional[datetime] = None
    dwell_time_sec:      Optional[float] = None   # time from first_seen → first_detected_at

    # Enrichment from MITRE store
    mitre_name:     str = ""
    mitre_tactics:  list[str] = field(default_factory=list)
    mitre_platforms: list[str] = field(default_factory=list)
    mitre_url:      str = ""

    @property
    def was_detected(self) -> bool:
        return self.detections > 0

    @property
    def detection_rate(self) -> float:
        if self.executions == 0:
            return 0.0
        return min(self.detections / self.executions, 1.0)


class MitreMapper:
    """
    Session-scoped MITRE ATT&CK coverage tracker.

    Thread-safe for asyncio (single-threaded event loop) — no locks needed.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._techniques: dict[str, TechniqueRecord] = {}
        self._step_count = 0
        self._alert_count = 0

    # ── Block 2 hook ─────────────────────────────────────────────────────────

    def record_step(self, step: AttackStep) -> None:
        """
        Called once per AttackStep from the attack engine.
        Registers the technique and increments execution counts.
        """
        tid = step.technique_id
        if not tid:
            return

        now = step.timestamp or datetime.now(timezone.utc)

        if tid not in self._techniques:
            # Enrich from the MITRE store
            info = technique_store.get(tid) or {}
            self._techniques[tid] = TechniqueRecord(
                technique_id    = tid,
                technique_name  = step.technique_name or info.get("name", tid),
                tactic          = step.tactic or (info.get("tactics", ["unknown"])[0]),
                phase           = step.phase,
                mitre_name      = info.get("name", ""),
                mitre_tactics   = info.get("tactics", []),
                mitre_platforms = info.get("platforms", []),
                mitre_url       = info.get("url", ""),
                first_seen      = now,
            )

        rec = self._techniques[tid]
        rec.executions += 1
        rec.last_seen   = now
        if step.success:
            rec.successful_executions += 1

        self._step_count += 1

    # ── Block 4 hook ─────────────────────────────────────────────────────────

    def record_detection(self, alert: AlertSchema) -> None:
        """
        Called when the detection engine fires an alert.
        Marks the associated technique as detected and records dwell time.
        """
        tid = alert.technique_id
        if not tid or tid not in self._techniques:
            return

        now = alert.timestamp or datetime.now(timezone.utc)
        rec = self._techniques[tid]
        rec.detections += 1
        self._alert_count += 1

        if rec.first_detected_at is None:
            rec.first_detected_at = now
            # Dwell time = gap between first execution and first detection
            if rec.first_seen:
                delta = (now - rec.first_seen).total_seconds()
                rec.dwell_time_sec = max(0.0, delta)

    # ── Summary reads (consumed by Scorer + API) ──────────────────────────────

    def coverage_summary(self) -> dict[str, Any]:
        """
        Return a flat summary dict consumed by:
          - SessionScorer.compute()
          - GET /mitre/coverage/{session_id}
        """
        used     = set(self._techniques.keys())
        detected = {tid for tid, r in self._techniques.items() if r.was_detected}
        missed   = used - detected

        coverage_pct = (len(detected) / len(used) * 100.0) if used else 0.0

        # Per-tactic breakdown
        by_tactic: dict[str, dict[str, int]] = defaultdict(lambda: {"used": 0, "detected": 0})
        for tid, rec in self._techniques.items():
            for tactic in rec.mitre_tactics or [rec.tactic]:
                by_tactic[tactic]["used"] += 1
                if rec.was_detected:
                    by_tactic[tactic]["detected"] += 1

        # Dwell times for detected techniques
        dwell_times = [
            r.dwell_time_sec for r in self._techniques.values()
            if r.dwell_time_sec is not None
        ]
        mean_dwell = sum(dwell_times) / len(dwell_times) if dwell_times else 0.0

        return {
            "session_id":             self.session_id,
            "techniques_used":        sorted(used),
            "techniques_detected":    sorted(detected),
            "techniques_missed":      sorted(missed),
            "techniques_used_count":  len(used),
            "techniques_detected_count": len(detected),
            "coverage_pct":           round(coverage_pct, 1),
            "by_tactic":              dict(by_tactic),
            "mean_dwell_time_sec":    round(mean_dwell, 1),
            "total_steps":            self._step_count,
            "total_detections":       self._alert_count,
        }

    def matrix_view(self) -> list[dict[str, Any]]:
        """
        Return a list of per-technique dicts suitable for rendering
        an ATT&CK Navigator-style heatmap in the dashboard.

        Each dict has: id, name, tactic, phase, executions,
                       detections, was_detected, dwell_time_sec, url
        """
        return [
            {
                "id":             rec.technique_id,
                "name":           rec.mitre_name or rec.technique_name,
                "tactic":         rec.mitre_tactics[0] if rec.mitre_tactics else rec.tactic,
                "all_tactics":    rec.mitre_tactics,
                "phase":          rec.phase,
                "platforms":      rec.mitre_platforms,
                "url":            rec.mitre_url,
                "executions":     rec.executions,
                "successful":     rec.successful_executions,
                "detections":     rec.detections,
                "was_detected":   rec.was_detected,
                "dwell_time_sec": rec.dwell_time_sec,
                "first_seen":     rec.first_seen.isoformat() if rec.first_seen else None,
                "first_detected": rec.first_detected_at.isoformat() if rec.first_detected_at else None,
            }
            for rec in sorted(self._techniques.values(), key=lambda r: r.technique_id)
        ]

    def get_technique_record(self, technique_id: str) -> Optional[TechniqueRecord]:
        return self._techniques.get(technique_id)

    # ── Convenience props ─────────────────────────────────────────────────────

    @property
    def techniques_used(self) -> set[str]:
        return set(self._techniques.keys())

    @property
    def techniques_detected(self) -> set[str]:
        return {tid for tid, r in self._techniques.items() if r.was_detected}

    @property
    def coverage_pct(self) -> float:
        used = len(self._techniques)
        if not used:
            return 0.0
        return len(self.techniques_detected) / used * 100.0

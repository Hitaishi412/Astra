"""
core/scoring/calculator.py
───────────────────────────
Session performance scoring engine.

Takes raw session metrics (attack events, alerts, coverage data, dwell times)
and produces a structured ScoreResult with:
  - Six weighted sub-scores (detection rate, MTTD, FP rate, containment, report quality, coverage)
  - A composite total_score (0–100)
  - A letter grade (excellent / good / average / needs_improvement / poor)
  - A MITRE coverage percentage
  - A full breakdown dict for the debrief view

Score formula (weights from config/settings.py):
  total = (
    detection_rate    * w_det
  + mttd_score        * w_mttd        ← inverted: shorter MTTD = higher score
  + fp_score          * w_fp          ← inverted: fewer FPs = higher score
  + containment_score * w_contain
  + report_quality    * w_report
  + coverage_score    * w_coverage
  ) / sum_of_weights

We normalise by the sum-of-weights so the total is always in [0, 100]
even if weights don't perfectly sum to 1 in config.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from config.constants import SCORE_THRESHOLDS
from config.settings import get_settings


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class ScoreResult:
    """
    Fully computed session score.
    Call .to_db_dict() to get a dict for crud.create_score().
    """
    session_id: str

    # ── Sub-scores ────────────────────────────────────────────────────────────
    detection_rate:           float = 0.0   # 0.0–1.0 fraction of malicious techniques detected
    mean_time_to_detect_sec:  float = 0.0   # raw MTTD in seconds
    false_positive_rate:      float = 0.0   # FP alerts / total alerts (0–1)
    containment_score:        float = 0.0   # 0–100
    report_quality_score:     float = 0.0   # 0–100 (from Block 6)

    # ── MITRE coverage ────────────────────────────────────────────────────────
    mitre_techniques_used:      int   = 0
    mitre_techniques_detected:  int   = 0
    mitre_coverage_pct:         float = 0.0

    # ── Composite ─────────────────────────────────────────────────────────────
    total_score: float = 0.0
    grade:       str   = "pending"

    # ── Full breakdown (stored in DB Score.details JSON) ──────────────────────
    details: dict[str, Any] = field(default_factory=dict)

    def to_db_dict(self) -> dict:
        return {
            "session_id":              self.session_id,
            "total_score":             round(self.total_score, 2),
            "grade":                   self.grade,
            "detection_rate":          round(self.detection_rate, 4),
            "mean_time_to_detect_sec": round(self.mean_time_to_detect_sec, 1),
            "false_positive_rate":     round(self.false_positive_rate, 4),
            "containment_score":       round(self.containment_score, 2),
            "report_quality_score":    round(self.report_quality_score, 2),
            "mitre_techniques_used":   self.mitre_techniques_used,
            "mitre_techniques_detected": self.mitre_techniques_detected,
            "mitre_coverage_pct":      round(self.mitre_coverage_pct, 1),
            "details":                 self.details,
        }


# ─── Grade thresholds ─────────────────────────────────────────────────────────

def _assign_grade(score: float) -> str:
    for label, threshold in sorted(SCORE_THRESHOLDS.items(), key=lambda x: -x[1]):
        if score >= threshold:
            return label
    return "poor"


# ─── MTTD normalisation ───────────────────────────────────────────────────────
# Maps raw mean-time-to-detect (seconds) to a 0–100 score.
# 0 s  → 100 (instant detection)
# 300 s → ~50  (5 minutes)
# 900 s → ~10  (15 minutes — poor)
# >1800 s → 0  (30+ minutes — no credit)

_MTTD_HALF_LIFE = 300.0   # seconds at which score is ~50


def _mttd_to_score(mttd_sec: float) -> float:
    if mttd_sec <= 0:
        return 100.0
    score = 100.0 * math.exp(-math.log(2) * mttd_sec / _MTTD_HALF_LIFE)
    return max(0.0, min(100.0, score))


# ─── FP rate normalisation ────────────────────────────────────────────────────
# 0% FP → 100 points; 50%+ FP → 0 points (linear)

def _fp_rate_to_score(fp_rate: float) -> float:
    return max(0.0, 100.0 * (1.0 - fp_rate * 2.0))


# ─── Containment score ────────────────────────────────────────────────────────
# Rewards stopping the attack at an early kill-chain phase.
# If the attacker reached Impact / Exfiltration without being stopped → low score.
# If the attack was contained at Delivery or Exploitation → high score.

_PHASE_PENALTY = {
    "reconnaissance":      0,
    "delivery":            5,
    "exploitation":        15,
    "installation":        25,
    "command_and_control": 40,
    "actions_on_objectives": 60,
}

_MAX_PHASE_PENALTY = max(_PHASE_PENALTY.values())


def _containment_score(deepest_undetected_phase: Optional[str]) -> float:
    """
    Returns 0–100 based on how deep the attacker got undetected.
    Returns 0 for unknown phases (treat as worst case).
    """
    if deepest_undetected_phase is None:
        return 100.0   # Everything detected
    if deepest_undetected_phase not in _PHASE_PENALTY:
        return 0.0     # Unknown phase — be conservative
    penalty = _PHASE_PENALTY[deepest_undetected_phase]
    return max(0.0, 100.0 - (penalty / _MAX_PHASE_PENALTY) * 100.0)


# ─── SessionScorer ────────────────────────────────────────────────────────────

class SessionScorer:
    """
    Computes the full session score from raw DB records.

    Usage:
        scorer = SessionScorer(session_id)
        result = scorer.compute(
            attack_events        = attack_events,
            alerts               = alerts,
            coverage             = mapper.coverage_summary(),
            report_quality_score = 75.0,
            session_duration_sec = 1800,
        )
        await crud.create_score(db, **result.to_db_dict())
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._settings  = get_settings()

    def compute(
        self,
        attack_events:        list,      # list[AttackEvent] ORM objects or dicts
        alerts:               list,      # list[Alert] ORM objects or dicts
        coverage:             dict,      # from MitreMapper.coverage_summary()
        report_quality_score: float = 0.0,
        session_duration_sec: float = 0.0,
    ) -> ScoreResult:
        """
        Main entry point. Returns a fully populated ScoreResult.
        """
        s = self._settings

        # ── 1. Detection rate ────────────────────────────────────────────────
        total_malicious = len([e for e in attack_events if _attr(e, "success", True)])
        tp_alerts       = [a for a in alerts if _attr(a, "is_true_positive") is True]
        detected_events = len(tp_alerts)
        detection_rate  = detected_events / total_malicious if total_malicious else 0.0
        detection_score = min(100.0, detection_rate * 100.0)

        # ── 2. Mean time to detect (MTTD) ────────────────────────────────────
        mttd_sec   = coverage.get("mean_dwell_time_sec", 0.0)
        mttd_score = _mttd_to_score(mttd_sec)

        # ── 3. False positive rate ────────────────────────────────────────────
        total_alerts = len(alerts)
        fp_count     = len([a for a in alerts if _attr(a, "is_true_positive") is False])
        fp_rate      = fp_count / total_alerts if total_alerts else 0.0
        fp_score     = _fp_rate_to_score(fp_rate)

        # ── 4. Containment score ─────────────────────────────────────────────
        # Find the deepest kill-chain phase that was executed but NOT detected
        detected_techniques = set(coverage.get("techniques_detected", []))
        undetected_events   = [
            e for e in attack_events
            if _attr(e, "technique_id", "") not in detected_techniques
        ]
        deepest_phase = _deepest_phase(undetected_events) if undetected_events else None
        contain_score = _containment_score(deepest_phase)

        # ── 5. MITRE coverage ────────────────────────────────────────────────
        n_used     = coverage.get("techniques_used_count", 0)
        n_detected = coverage.get("techniques_detected_count", 0)
        cov_pct    = coverage.get("coverage_pct", 0.0)
        coverage_score = float(cov_pct)  # already 0–100

        # ── 6. Report quality (pass-through from Block 6) ─────────────────────
        report_score = max(0.0, min(100.0, report_quality_score))

        # ── 7. Weighted composite (normalised by weight sum) ──────────────────
        weights = {
            "detection":   s.weight_detection_rate,
            "mttd":        s.weight_mttd,
            "fp":          s.weight_fp_rate,
            "containment": s.weight_containment,
            "report":      s.weight_report_quality,
            "coverage":    s.weight_coverage,
        }
        weight_sum = sum(weights.values())
        if weight_sum <= 0:
            weight_sum = 1.0  # Safety: never divide by zero

        weighted_total = (
            detection_score * weights["detection"]
            + mttd_score    * weights["mttd"]
            + fp_score      * weights["fp"]
            + contain_score * weights["containment"]
            + report_score  * weights["report"]
            + coverage_score * weights["coverage"]
        )
        total = weighted_total / weight_sum
        total = max(0.0, min(100.0, total))
        grade = _assign_grade(total)

        # ── 8. Full breakdown for debrief ────────────────────────────────────
        details = {
            "weights": weights,
            "weight_sum": round(weight_sum, 4),
            "sub_scores": {
                "detection_score":   round(detection_score, 2),
                "mttd_score":        round(mttd_score, 2),
                "fp_score":          round(fp_score, 2),
                "containment_score": round(contain_score, 2),
                "report_score":      round(report_score, 2),
                "coverage_score":    round(coverage_score, 2),
            },
            "raw_metrics": {
                "total_attack_steps":      len(attack_events),
                "successful_attack_steps": total_malicious,
                "total_alerts":            total_alerts,
                "true_positive_alerts":    detected_events,
                "false_positive_alerts":   fp_count,
                "fp_rate":                 round(fp_rate, 4),
                "mttd_sec":                round(mttd_sec, 1),
                "session_duration_sec":    round(session_duration_sec, 1),
                "deepest_undetected_phase": deepest_phase,
            },
            "mitre": {
                "techniques_used":     n_used,
                "techniques_detected": n_detected,
                "coverage_pct":        round(cov_pct, 1),
                "by_tactic":           coverage.get("by_tactic", {}),
                "techniques_missed":   coverage.get("techniques_missed", []),
            },
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }

        return ScoreResult(
            session_id               = self.session_id,
            detection_rate           = round(detection_rate, 4),
            mean_time_to_detect_sec  = round(mttd_sec, 1),
            false_positive_rate      = round(fp_rate, 4),
            containment_score        = round(contain_score, 2),
            report_quality_score     = round(report_score, 2),
            mitre_techniques_used    = n_used,
            mitre_techniques_detected= n_detected,
            mitre_coverage_pct       = round(cov_pct, 1),
            total_score              = round(total, 2),
            grade                    = grade,
            details                  = details,
        )

    # ── Incremental update (called per-alert for live score preview) ──────────

    def quick_score(
        self,
        tp_count:   int,
        fp_count:   int,
        total_steps: int,
        mttd_sec:   float,
        coverage_pct: float = 0.0,
    ) -> dict[str, Any]:
        """
        Lightweight score estimate for live dashboard preview.
        Does NOT write to DB — used only for the streaming score channel.
        """
        s = self._settings
        detection_rate  = tp_count / total_steps if total_steps else 0.0
        detection_score = detection_rate * 100.0
        total_alerts    = tp_count + fp_count
        fp_rate         = fp_count / total_alerts if total_alerts else 0.0
        mttd_score_val  = _mttd_to_score(mttd_sec)
        fp_score_val    = _fp_rate_to_score(fp_rate)

        weight_sum = (
            s.weight_detection_rate
            + s.weight_mttd
            + s.weight_fp_rate
            + s.weight_coverage
        )
        if weight_sum <= 0:
            weight_sum = 1.0

        total = (
            detection_score * s.weight_detection_rate
            + mttd_score_val * s.weight_mttd
            + fp_score_val   * s.weight_fp_rate
            + coverage_pct   * s.weight_coverage
        ) / weight_sum

        total = max(0.0, min(100.0, total))

        return {
            "total_score":    round(total, 1),
            "grade":          _assign_grade(total),
            "detection_rate": round(detection_rate * 100.0, 1),
            "fp_rate":        round(fp_rate * 100.0, 1),
            "mttd_sec":       round(mttd_sec, 1),
        }


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Get attribute from ORM object or dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


_PHASE_ORDER = [
    "reconnaissance",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]


def _deepest_phase(events: list) -> Optional[str]:
    """Return the deepest kill-chain phase reached by the given events."""
    phases_seen = {_attr(e, "phase", "") for e in events}
    for phase in reversed(_PHASE_ORDER):
        if phase in phases_seen:
            return phase
    return None

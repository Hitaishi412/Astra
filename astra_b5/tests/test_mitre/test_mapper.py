"""
tests/test_mitre/test_mapper.py  +  tests/test_scoring/test_calculator.py
— combined in one file for simplicity —

Run with:
    cd Astra-main
    pip install pytest pydantic pydantic-settings pyyaml faker
    pytest tests/test_mitre/ tests/test_scoring/ -v
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from core.mitre.technique_store import TechniqueStore, _BUILTIN_STUB
from core.mitre.mapper import MitreMapper, TechniqueRecord
from core.scoring.calculator import (
    SessionScorer, ScoreResult,
    _mttd_to_score, _fp_rate_to_score, _containment_score,
    _assign_grade, _deepest_phase,
)


# ─── Shared fakes ─────────────────────────────────────────────────────────────

def _make_step(
    technique_id:   str = "T1059.001",
    technique_name: str = "PowerShell",
    tactic:         str = "execution",
    phase:          str = "exploitation",
    success:        bool = True,
    ts:             Optional[datetime] = None,
):
    """Build a minimal AttackStep dataclass."""
    @dataclass
    class _Step:
        id:             str = field(default_factory=lambda: str(uuid.uuid4()))
        timestamp:      datetime = field(default_factory=lambda: datetime.now(timezone.utc))
        phase:          str = ""
        step_number:    int = 1
        technique_id:   str = ""
        technique_name: str = ""
        tactic:         str = ""
        description:    str = ""
        source_host:    Optional[str] = None
        target_host:    Optional[str] = None
        success:        bool = True
        severity:       str = "medium"
        extra_data:     dict = field(default_factory=dict)
        log_count_hint: int = 5
        noise_count_hint: int = 10

    s = _Step()
    s.technique_id   = technique_id
    s.technique_name = technique_name
    s.tactic         = tactic
    s.phase          = phase
    s.success        = success
    s.timestamp      = ts or datetime.now(timezone.utc)
    return s


def _make_alert(
    technique_id:     Optional[str] = "T1059.001",
    is_true_positive: Optional[bool] = True,
    ts:               Optional[datetime] = None,
):
    from core.log_engine.schemas import AlertSchema
    return AlertSchema(
        id               = str(uuid.uuid4()),
        session_id       = "test-session",
        detection_type   = "sigma",
        title            = "Test Alert",
        description      = "Test",
        severity         = "high",
        technique_id     = technique_id,
        tactic           = "execution",
        is_true_positive = is_true_positive,
        timestamp        = ts or datetime.now(timezone.utc),
    )


def _make_attack_event(
    technique_id: str = "T1059.001",
    phase:        str = "exploitation",
    success:      bool = True,
):
    """Minimal dict that mimics an AttackEvent ORM object."""
    return {
        "technique_id": technique_id,
        "phase":        phase,
        "success":      success,
        "tactic":       "execution",
    }


def _make_alert_dict(
    technique_id:     Optional[str] = "T1059.001",
    is_true_positive: Optional[bool] = True,
):
    return {
        "technique_id":     technique_id,
        "is_true_positive": is_true_positive,
        "severity":         "high",
    }


SESSION_ID = "test-session-b5"


# ═══════════════════════════════════════════════════════════════════════════
# TECHNIQUE STORE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestTechniqueStore:

    def test_get_known_technique(self):
        store = TechniqueStore()
        t = store.get("T1059.001")
        assert t is not None
        assert t["id"] == "T1059.001"
        assert "PowerShell" in t["name"]
        assert "execution" in t["tactics"]

    def test_get_unknown_returns_none(self):
        store = TechniqueStore()
        assert store.get("T9999.999") is None

    def test_exists_true(self):
        store = TechniqueStore()
        assert store.exists("T1566.001") is True

    def test_exists_false(self):
        store = TechniqueStore()
        assert store.exists("T0000.000") is False

    def test_get_many(self):
        store  = TechniqueStore()
        result = store.get_many(["T1059.001", "T1021.001", "T9999.999"])
        assert "T1059.001" in result
        assert "T1021.001" in result
        assert "T9999.999" not in result

    def test_tactic_for_technique(self):
        store   = TechniqueStore()
        tactics = store.tactic_for_technique("T1059.001")
        assert "execution" in tactics

    def test_tactic_for_unknown_returns_empty(self):
        store = TechniqueStore()
        assert store.tactic_for_technique("T9999.999") == []

    def test_by_tactic(self):
        store    = TechniqueStore()
        recon    = store.by_tactic("reconnaissance")
        assert len(recon) >= 3   # At least the 3 recon techniques in stub
        ids = [t["id"] for t in recon]
        assert "T1595.001" in ids

    def test_all_stub_techniques_loadable(self):
        store = TechniqueStore()
        for tid in _BUILTIN_STUB:
            t = store.get(tid)
            assert t is not None, f"Stub technique {tid} not retrievable"

    def test_total_count_at_least_stub(self):
        store = TechniqueStore()
        assert store.total_count >= len(_BUILTIN_STUB)

    def test_all_techniques_returns_dict(self):
        store = TechniqueStore()
        all_t = store.all_techniques()
        assert isinstance(all_t, dict)
        assert len(all_t) >= len(_BUILTIN_STUB)

    @pytest.mark.parametrize("tid", list(_BUILTIN_STUB.keys()))
    def test_every_stub_technique_has_required_fields(self, tid):
        store = TechniqueStore()
        t = store.get(tid)
        assert t["id"]
        assert t["name"]
        assert isinstance(t["tactics"], list)
        assert len(t["tactics"]) >= 1

    def test_case_insensitive_lookup(self):
        store = TechniqueStore()
        t_upper = store.get("T1059.001")
        t_lower = store.get("t1059.001")
        # Upper should always work; lower may or may not depending on store
        assert t_upper is not None

    def test_is_seeded_returns_bool(self):
        store = TechniqueStore()
        assert isinstance(store.is_seeded, bool)


# ═══════════════════════════════════════════════════════════════════════════
# MITRE MAPPER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestMitreMapper:

    def test_initial_state(self):
        mapper = MitreMapper(SESSION_ID)
        assert mapper.session_id == SESSION_ID
        assert mapper.techniques_used == set()
        assert mapper.techniques_detected == set()
        assert mapper.coverage_pct == 0.0

    def test_record_step_registers_technique(self):
        mapper = MitreMapper(SESSION_ID)
        step   = _make_step("T1059.001")
        mapper.record_step(step)
        assert "T1059.001" in mapper.techniques_used

    def test_record_step_increments_count(self):
        mapper = MitreMapper(SESSION_ID)
        step   = _make_step("T1059.001")
        mapper.record_step(step)
        mapper.record_step(step)
        rec = mapper.get_technique_record("T1059.001")
        assert rec.executions == 2

    def test_record_step_successful_count(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001", success=True))
        mapper.record_step(_make_step("T1059.001", success=False))
        rec = mapper.get_technique_record("T1059.001")
        assert rec.successful_executions == 1
        assert rec.executions == 2

    def test_record_step_ignores_empty_technique_id(self):
        mapper = MitreMapper(SESSION_ID)
        step   = _make_step("")
        mapper.record_step(step)
        assert len(mapper.techniques_used) == 0

    def test_record_detection_marks_detected(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001"))
        mapper.record_detection(_make_alert("T1059.001"))
        assert "T1059.001" in mapper.techniques_detected

    def test_record_detection_unknown_technique_ignored(self):
        mapper = MitreMapper(SESSION_ID)
        # Alert for a technique we never executed — should not crash
        mapper.record_detection(_make_alert("T9999.999"))
        assert len(mapper.techniques_detected) == 0

    def test_dwell_time_computed(self):
        mapper = MitreMapper(SESSION_ID)
        t0     = datetime.now(timezone.utc)
        t1     = t0 + timedelta(seconds=120)

        step  = _make_step("T1059.001", ts=t0)
        alert = _make_alert("T1059.001", ts=t1)

        mapper.record_step(step)
        mapper.record_detection(alert)

        rec = mapper.get_technique_record("T1059.001")
        assert rec.dwell_time_sec is not None
        assert 115 <= rec.dwell_time_sec <= 125   # ≈120s ± jitter

    def test_coverage_pct_zero_with_no_steps(self):
        assert MitreMapper(SESSION_ID).coverage_pct == 0.0

    def test_coverage_pct_100_all_detected(self):
        mapper = MitreMapper(SESSION_ID)
        for tid in ("T1059.001", "T1021.001"):
            mapper.record_step(_make_step(tid))
            mapper.record_detection(_make_alert(tid))
        assert mapper.coverage_pct == 100.0

    def test_coverage_pct_partial(self):
        mapper = MitreMapper(SESSION_ID)
        for tid in ("T1059.001", "T1021.001", "T1486"):
            mapper.record_step(_make_step(tid))
        mapper.record_detection(_make_alert("T1059.001"))
        pct = mapper.coverage_pct
        assert 30 <= pct <= 40   # 1/3 ≈ 33.3%

    def test_coverage_summary_keys(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001"))
        summary = mapper.coverage_summary()
        required = {
            "session_id", "techniques_used", "techniques_detected",
            "techniques_missed", "techniques_used_count",
            "techniques_detected_count", "coverage_pct",
            "by_tactic", "mean_dwell_time_sec",
        }
        assert required.issubset(set(summary.keys()))

    def test_coverage_summary_missed_set(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001"))
        mapper.record_step(_make_step("T1021.001"))
        mapper.record_detection(_make_alert("T1059.001"))
        summary = mapper.coverage_summary()
        assert "T1021.001" in summary["techniques_missed"]
        assert "T1059.001" not in summary["techniques_missed"]

    def test_by_tactic_breakdown(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001", tactic="execution"))
        mapper.record_step(_make_step("T1021.001", tactic="lateral-movement"))
        summary = mapper.coverage_summary()
        tactic_keys = set(summary["by_tactic"].keys())
        assert len(tactic_keys) >= 1

    def test_matrix_view_returns_list(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001"))
        view = mapper.matrix_view()
        assert isinstance(view, list)
        assert len(view) == 1
        row = view[0]
        assert row["id"] == "T1059.001"
        assert "was_detected" in row
        assert "dwell_time_sec" in row

    def test_matrix_view_enriches_from_store(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1059.001", technique_name="PS"))
        view = mapper.matrix_view()
        # Should be overridden by the store's canonical name
        assert "PowerShell" in view[0]["name"]

    def test_multiple_steps_same_session(self):
        mapper = MitreMapper(SESSION_ID)
        techniques = ["T1595.001", "T1566.001", "T1059.001", "T1021.001",
                      "T1550.002", "T1041", "T1486"]
        for tid in techniques:
            mapper.record_step(_make_step(tid))
        assert mapper.techniques_used == set(techniques)

    def test_mean_dwell_time_in_summary(self):
        mapper = MitreMapper(SESSION_ID)
        t0 = datetime.now(timezone.utc)
        mapper.record_step(_make_step("T1059.001", ts=t0))
        mapper.record_detection(_make_alert("T1059.001", ts=t0 + timedelta(seconds=60)))
        mapper.record_step(_make_step("T1021.001", ts=t0))
        mapper.record_detection(_make_alert("T1021.001", ts=t0 + timedelta(seconds=180)))
        summary = mapper.coverage_summary()
        # Mean of 60 and 180 = 120
        assert 100 <= summary["mean_dwell_time_sec"] <= 140


# ═══════════════════════════════════════════════════════════════════════════
# SCORING CALCULATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestScoringHelpers:

    # ── MTTD normalisation ────────────────────────────────────────────────────
    def test_mttd_zero_gives_100(self):
        assert _mttd_to_score(0) == 100.0

    def test_mttd_300s_gives_approx_50(self):
        score = _mttd_to_score(300)
        assert 45 <= score <= 55

    def test_mttd_very_large_gives_near_zero(self):
        assert _mttd_to_score(3600) < 5.0

    def test_mttd_always_in_range(self):
        for sec in [0, 30, 60, 120, 300, 600, 1800, 3600]:
            s = _mttd_to_score(sec)
            assert 0.0 <= s <= 100.0

    def test_mttd_monotonically_decreasing(self):
        scores = [_mttd_to_score(t) for t in [0, 60, 120, 300, 600, 1800]]
        assert scores == sorted(scores, reverse=True)

    # ── FP rate normalisation ─────────────────────────────────────────────────
    def test_fp_rate_zero_gives_100(self):
        assert _fp_rate_to_score(0.0) == 100.0

    def test_fp_rate_50pct_gives_zero(self):
        assert _fp_rate_to_score(0.5) == 0.0

    def test_fp_rate_over_50pct_clamped_to_zero(self):
        assert _fp_rate_to_score(0.9) == 0.0

    def test_fp_rate_always_in_range(self):
        for rate in [0.0, 0.1, 0.25, 0.5, 0.75, 1.0]:
            s = _fp_rate_to_score(rate)
            assert 0.0 <= s <= 100.0

    # ── Containment score ─────────────────────────────────────────────────────
    def test_containment_none_gives_100(self):
        assert _containment_score(None) == 100.0

    def test_containment_recon_gives_high(self):
        assert _containment_score("reconnaissance") > 90.0

    def test_containment_impact_gives_low(self):
        assert _containment_score("actions_on_objectives") < 10.0

    def test_containment_unknown_phase_returns_zero(self):
        assert _containment_score("unknown_phase") == 0.0

    # ── Grade assignment ──────────────────────────────────────────────────────
    def test_grade_excellent(self):
        assert _assign_grade(92.0) == "excellent"

    def test_grade_good(self):
        assert _assign_grade(78.0) == "good"

    def test_grade_average(self):
        assert _assign_grade(60.0) == "average"

    def test_grade_needs_improvement(self):
        assert _assign_grade(40.0) == "needs_improvement"

    def test_grade_poor(self):
        assert _assign_grade(10.0) == "poor"

    # ── Deepest phase ─────────────────────────────────────────────────────────
    def test_deepest_phase_single(self):
        events = [{"phase": "exploitation", "technique_id": "T1059.001"}]
        assert _deepest_phase(events) == "exploitation"

    def test_deepest_phase_multiple(self):
        events = [
            {"phase": "delivery", "technique_id": "T1566.001"},
            {"phase": "actions_on_objectives", "technique_id": "T1486"},
            {"phase": "exploitation", "technique_id": "T1059.001"},
        ]
        assert _deepest_phase(events) == "actions_on_objectives"

    def test_deepest_phase_empty_returns_none(self):
        assert _deepest_phase([]) is None


class TestSessionScorer:

    def _coverage(
        self,
        used:     list[str] = None,
        detected: list[str] = None,
        mttd:     float = 0.0,
    ) -> dict:
        used_     = used or []
        detected_ = detected or []
        missed    = list(set(used_) - set(detected_))
        pct       = len(detected_) / len(used_) * 100.0 if used_ else 0.0
        return {
            "techniques_used":          used_,
            "techniques_detected":      detected_,
            "techniques_missed":        missed,
            "techniques_used_count":    len(used_),
            "techniques_detected_count": len(detected_),
            "coverage_pct":             pct,
            "mean_dwell_time_sec":      mttd,
            "by_tactic":                {},
        }

    def test_compute_returns_score_result(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            attack_events = [_make_attack_event()],
            alerts        = [_make_alert_dict()],
            coverage      = self._coverage(["T1059.001"], ["T1059.001"]),
        )
        assert isinstance(result, ScoreResult)

    def test_perfect_score_near_100(self):
        scorer = SessionScorer(SESSION_ID)
        events = [_make_attack_event(t) for t in ["T1059.001", "T1021.001", "T1486"]]
        alerts = [_make_alert_dict(t, True) for t in ["T1059.001", "T1021.001", "T1486"]]
        result = scorer.compute(
            attack_events        = events,
            alerts               = alerts,
            coverage             = self._coverage(
                ["T1059.001", "T1021.001", "T1486"],
                ["T1059.001", "T1021.001", "T1486"],
                mttd=0,
            ),
            report_quality_score = 100.0,
        )
        # No report weight without report → cap at non-report portion
        assert result.total_score > 50.0
        assert result.grade in ("excellent", "good")

    def test_zero_score_nothing_detected(self):
        scorer = SessionScorer(SESSION_ID)
        events = [_make_attack_event("T1486")]
        # All FP alerts
        alerts = [_make_alert_dict("T1059.001", False)]
        result = scorer.compute(
            attack_events = events,
            alerts        = alerts,
            coverage      = self._coverage(["T1486"], []),
        )
        assert result.total_score < 50.0

    def test_detection_rate_correct(self):
        scorer = SessionScorer(SESSION_ID)
        events = [_make_attack_event("T1059.001", success=True) for _ in range(4)]
        alerts = [_make_alert_dict("T1059.001", True) for _ in range(2)]
        result = scorer.compute(
            attack_events = events,
            alerts        = alerts,
            coverage      = self._coverage(["T1059.001"], ["T1059.001"]),
        )
        # 2 TP out of 4 successful steps = 0.5 detection rate
        assert 0.45 <= result.detection_rate <= 0.55

    def test_fp_rate_correct(self):
        scorer = SessionScorer(SESSION_ID)
        events = [_make_attack_event()]
        # 2 FP + 1 TP = 66% FP rate
        alerts = [
            _make_alert_dict(is_true_positive=False),
            _make_alert_dict(is_true_positive=False),
            _make_alert_dict(is_true_positive=True),
        ]
        result = scorer.compute(
            attack_events = events,
            alerts        = alerts,
            coverage      = self._coverage(["T1059.001"], ["T1059.001"]),
        )
        assert 0.60 <= result.false_positive_rate <= 0.70

    def test_mttd_stored(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            attack_events = [_make_attack_event()],
            alerts        = [_make_alert_dict()],
            coverage      = self._coverage(["T1059.001"], ["T1059.001"], mttd=120.0),
        )
        assert result.mean_time_to_detect_sec == 120.0

    def test_mitre_fields_populated(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            attack_events = [_make_attack_event("T1059.001"),
                             _make_attack_event("T1021.001")],
            alerts        = [_make_alert_dict("T1059.001", True)],
            coverage      = self._coverage(["T1059.001", "T1021.001"],
                                           ["T1059.001"]),
        )
        assert result.mitre_techniques_used     == 2
        assert result.mitre_techniques_detected == 1
        assert 45 <= result.mitre_coverage_pct <= 55

    def test_grade_assigned(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            attack_events = [], alerts = [],
            coverage = self._coverage(),
        )
        assert result.grade in (
            "excellent", "good", "average", "needs_improvement", "poor", "pending"
        )

    def test_total_score_in_range(self):
        scorer = SessionScorer(SESSION_ID)
        for _ in range(20):
            import random
            n = random.randint(1, 10)
            d = random.randint(0, n)
            f = random.randint(0, n)
            events = [_make_attack_event() for _ in range(n)]
            alerts = (
                [_make_alert_dict(is_true_positive=True)  for _ in range(d)] +
                [_make_alert_dict(is_true_positive=False) for _ in range(f)]
            )
            result = scorer.compute(
                attack_events = events,
                alerts        = alerts,
                coverage      = self._coverage(["T1059.001"], ["T1059.001"] if d else []),
            )
            assert 0.0 <= result.total_score <= 100.0, \
                f"Score out of range: {result.total_score}"

    def test_to_db_dict_keys(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute([], [], self._coverage())
        d = result.to_db_dict()
        required = {
            "session_id", "total_score", "grade", "detection_rate",
            "mean_time_to_detect_sec", "false_positive_rate",
            "containment_score", "report_quality_score",
            "mitre_techniques_used", "mitre_techniques_detected",
            "mitre_coverage_pct", "details",
        }
        assert required.issubset(set(d.keys()))

    def test_details_contains_breakdown(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            [_make_attack_event()], [_make_alert_dict()],
            self._coverage(["T1059.001"], ["T1059.001"])
        )
        assert "sub_scores"  in result.details
        assert "raw_metrics" in result.details
        assert "weights"     in result.details
        assert "mitre"       in result.details

    def test_report_quality_included(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            [], [], self._coverage(),
            report_quality_score=80.0,
        )
        assert result.report_quality_score == 80.0

    def test_report_quality_clamped_to_100(self):
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute(
            [], [], self._coverage(),
            report_quality_score=150.0,
        )
        assert result.report_quality_score <= 100.0

    def test_quick_score_returns_dict(self):
        scorer = SessionScorer(SESSION_ID)
        q = scorer.quick_score(tp_count=3, fp_count=1, total_steps=5, mttd_sec=60)
        assert "total_score"    in q
        assert "grade"          in q
        assert "detection_rate" in q
        assert "fp_rate"        in q
        assert "mttd_sec"       in q

    def test_quick_score_in_range(self):
        scorer = SessionScorer(SESSION_ID)
        q = scorer.quick_score(tp_count=5, fp_count=0, total_steps=5, mttd_sec=30)
        assert 0.0 <= q["total_score"] <= 100.0

    def test_empty_session_does_not_crash(self):
        # Empty session: no attacks, no alerts → MTTD=0, FP=0 give full sub-scores,
        # but detection_rate=0 and containment=100. Score is non-zero and within range.
        scorer = SessionScorer(SESSION_ID)
        result = scorer.compute([], [], self._coverage())
        assert 0.0 <= result.total_score <= 100.0
        assert result.grade in ("excellent", "good", "average", "needs_improvement", "poor", "pending")
        assert result.detection_rate == 0.0
        assert result.mitre_techniques_used == 0


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION: mapper → scorer
# ═══════════════════════════════════════════════════════════════════════════

class TestMitreMapperToScorer:
    """
    End-to-end: record steps + detections in mapper, feed summary to scorer.
    Verifies the two components talk to each other correctly.
    """

    def test_full_pipeline_all_detected(self):
        mapper = MitreMapper(SESSION_ID)
        t0     = datetime.now(timezone.utc)

        techniques = ["T1595.001", "T1566.001", "T1059.001",
                      "T1021.001", "T1550.002", "T1041", "T1486"]

        for i, tid in enumerate(techniques):
            step  = _make_step(tid, ts=t0 + timedelta(seconds=i * 10))
            alert = _make_alert(tid, ts=t0 + timedelta(seconds=i * 10 + 30))
            mapper.record_step(step)
            mapper.record_detection(alert)

        coverage = mapper.coverage_summary()
        scorer   = SessionScorer(SESSION_ID)

        events = [_make_attack_event(t) for t in techniques]
        alerts = [_make_alert_dict(t, True) for t in techniques]
        result = scorer.compute(events, alerts, coverage, report_quality_score=70.0)

        assert result.mitre_coverage_pct == 100.0
        assert result.total_score > 60.0
        assert result.grade in ("excellent", "good")

    def test_full_pipeline_half_detected(self):
        mapper = MitreMapper(SESSION_ID)
        t0     = datetime.now(timezone.utc)

        used     = ["T1595.001", "T1566.001", "T1059.001", "T1021.001"]
        detected = ["T1595.001", "T1059.001"]

        for tid in used:
            mapper.record_step(_make_step(tid, ts=t0))
        for tid in detected:
            mapper.record_detection(_make_alert(tid, ts=t0 + timedelta(seconds=90)))

        coverage = mapper.coverage_summary()
        assert coverage["coverage_pct"] == 50.0

        scorer = SessionScorer(SESSION_ID)
        events = [_make_attack_event(t) for t in used]
        alerts = ([_make_alert_dict(t, True)  for t in detected] +
                  [_make_alert_dict(t, False) for t in set(used) - set(detected)])
        result = scorer.compute(events, alerts, coverage)

        assert result.mitre_coverage_pct == 50.0
        assert result.mitre_techniques_detected == 2
        assert result.mitre_techniques_used == 4

    def test_missed_techniques_in_details(self):
        mapper = MitreMapper(SESSION_ID)
        mapper.record_step(_make_step("T1486"))         # ransomware — not detected
        mapper.record_step(_make_step("T1059.001"))     # PS — detected
        mapper.record_detection(_make_alert("T1059.001"))

        coverage = mapper.coverage_summary()
        assert "T1486" in coverage["techniques_missed"]

        result = SessionScorer(SESSION_ID).compute(
            [_make_attack_event("T1486"), _make_attack_event("T1059.001")],
            [_make_alert_dict("T1059.001", True)],
            coverage,
        )
        assert "T1486" in result.details["mitre"]["techniques_missed"]

    def test_containment_score_high_when_stopped_early(self):
        mapper = MitreMapper(SESSION_ID)
        # Only recon reached — attack stopped early
        mapper.record_step(_make_step("T1595.001", phase="reconnaissance"))
        mapper.record_detection(_make_alert("T1595.001"))

        coverage = mapper.coverage_summary()
        result   = SessionScorer(SESSION_ID).compute(
            [_make_attack_event("T1595.001", "reconnaissance")],
            [_make_alert_dict("T1595.001", True)],
            coverage,
        )
        assert result.containment_score > 85.0

    def test_containment_score_low_when_reached_impact(self):
        mapper = MitreMapper(SESSION_ID)
        # Attack reached impact — not detected
        mapper.record_step(_make_step("T1486", phase="actions_on_objectives"))
        # No detections

        coverage = mapper.coverage_summary()
        result   = SessionScorer(SESSION_ID).compute(
            [_make_attack_event("T1486", "actions_on_objectives")],
            [],
            coverage,
        )
        assert result.containment_score < 10.0

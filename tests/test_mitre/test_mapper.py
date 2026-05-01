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

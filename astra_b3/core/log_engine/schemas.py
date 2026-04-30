"""
core/log_engine/schemas.py
───────────────────────────
The interface contract between Block 3 (Log Engine) and Block 4 (Detection Engine).

Block 3 produces LogEntry objects (synthetic AstraEvent logs).
Block 4 consumes them and emits Alert objects.

These schemas mirror the database models in db/models.py so a LogEntry can be
saved directly to the DB via crud.create_log_entry(**log.model_dump()).

DO NOT change these without coordinating across the team — they are the
single source of truth for log shape.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from config.constants import LogSource, Severity


# ─── Helper factories ────────────────────────────────────────────────────────
def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ════════════════════════════════════════════════════════════════════════════
# LOG ENTRY  —  what Block 3 emits and Block 4 consumes
# ════════════════════════════════════════════════════════════════════════════
class LogEntry(BaseModel):
    """
    A single AstraEvent log entry.

    Block 3 produces these from AttackStep objects + background noise.
    Block 4's detection pipeline consumes these to produce Alert objects.

    Field semantics:
        - `is_malicious`: True if this log was produced by an attack step.
          False if it's benign noise. The detection engine does NOT see this
          field during evaluation — it's used afterward for scoring (TP/FP).
        - `attack_event_id`: Links a malicious log back to the AttackStep that
          produced it. Used for correlation and the "what really happened"
          debrief view.
        - `raw_data`: Flexible JSON field for source-specific fields not in the
          common schema (e.g. Windows EventCode, Linux facility, PID, etc.)
    """
    # ── Identity ─────────────────────────────────────────────────────────────
    id: str = Field(default_factory=_uuid)
    session_id: str
    timestamp: datetime = Field(default_factory=_utcnow)

    # ── Source classification ────────────────────────────────────────────────
    source: str = Field(..., description="windows_event | linux_syslog | network_flow | cloud_audit | application | endpoint_edr")
    event_id: Optional[int] = Field(None, description="Numeric event code (e.g. Windows 4625, Sysmon 1)")
    severity: str = Field("info", description="info | low | medium | high | critical")
    category: Optional[str] = Field(None, description="authentication | process_creation | network | file_event | etc")

    # ── Content ──────────────────────────────────────────────────────────────
    message: str = Field(..., description="Human-readable log message")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Source-specific structured fields")

    # ── Common context fields (the Sigma engine queries these heavily) ───────
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    file_path: Optional[str] = None
    command_line: Optional[str] = None

    # ── Ground truth (used for scoring, not detection) ───────────────────────
    is_malicious: bool = False
    attack_event_id: Optional[str] = None

    # ── Validation ───────────────────────────────────────────────────────────
    @field_validator("source")
    @classmethod
    def _validate_source(cls, v: str) -> str:
        valid = {s.value for s in LogSource}
        if v not in valid:
            raise ValueError(f"source must be one of {valid}, got '{v}'")
        return v

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        valid = {s.value for s in Severity}
        if v not in valid:
            raise ValueError(f"severity must be one of {valid}, got '{v}'")
        return v

    # ── Helpers ──────────────────────────────────────────────────────────────
    def to_db_dict(self) -> dict:
        """Convert to a dict ready for db.crud.create_log_entry()."""
        return self.model_dump(mode="json")

    def matches_field(self, field_name: str, expected: Any) -> bool:
        """
        Used by the Sigma parser. Returns True if this log's field matches
        the expected value. Handles None, lists, and string contains.
        """
        actual = getattr(self, field_name, None)
        if actual is None:
            actual = self.raw_data.get(field_name)
        if actual is None:
            return False

        if isinstance(expected, list):
            return any(self._compare(actual, e) for e in expected)
        return self._compare(actual, expected)

    @staticmethod
    def _compare(actual: Any, expected: Any) -> bool:
        if isinstance(expected, str) and isinstance(actual, str):
            return expected.lower() in actual.lower()
        return actual == expected


# ════════════════════════════════════════════════════════════════════════════
# ALERT  —  what Block 4 emits when a detection fires
# ════════════════════════════════════════════════════════════════════════════
class AlertSchema(BaseModel):
    """
    An alert produced by the detection engine.

    Mirrors the Alert DB model. Block 4's pipeline emits these; the API
    streams them to the dashboard and persists them to the DB.
    """
    id: str = Field(default_factory=_uuid)
    session_id: str
    timestamp: datetime = Field(default_factory=_utcnow)

    # ── What triggered this alert ────────────────────────────────────────────
    detection_type: str = Field(..., description="sigma | anomaly | correlation")
    rule_id: Optional[str] = None  # Set if detection_type == 'sigma'
    rule_name: Optional[str] = None

    # ── Alert content ────────────────────────────────────────────────────────
    title: str
    description: str
    severity: str = "medium"

    # ── MITRE attribution (often pulled from the triggering rule) ────────────
    technique_id: Optional[str] = None
    tactic: Optional[str] = None

    # ── Context (extracted from the triggering log entries) ──────────────────
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None

    # ── Evidence: the log entries that triggered this alert ──────────────────
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Dict with 'log_ids' (list) and 'summary' (str)"
    )

    # ── Triage state (populated by the analyst, not the engine) ──────────────
    triage_status: str = "new"
    is_true_positive: Optional[bool] = None  # Determined by ground truth

    @field_validator("detection_type")
    @classmethod
    def _validate_detection_type(cls, v: str) -> str:
        valid = {"sigma", "anomaly", "correlation"}
        if v not in valid:
            raise ValueError(f"detection_type must be one of {valid}, got '{v}'")
        return v

    def to_db_dict(self) -> dict:
        """Convert to a dict ready for db.crud.create_alert()."""
        return self.model_dump(mode="json")

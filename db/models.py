"""
Database models — all tables for the ASTRA platform.
Uses SQLAlchemy 2.0 declarative style with async support.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(128))
    # Firebase Auth integration
    firebase_uid: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(256), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    sessions: Mapped[list["Session"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="user", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Training Session
# ---------------------------------------------------------------------------
class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "ransomware"
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # red_team / blue_team / full_spectrum
    difficulty: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="created")  # created/running/paused/completed/aborted

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # JSON field for session-specific config overrides
    config: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="sessions")
    attack_events: Mapped[list["AttackEvent"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    log_entries: Mapped[list["LogEntry"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    score: Mapped[Optional["Score"]] = relationship(back_populates="session", uselist=False, cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Attack Event (each step the attack engine executes)
# ---------------------------------------------------------------------------
class AttackEvent(Base):
    __tablename__ = "attack_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=False)

    # Kill chain position
    phase: Mapped[str] = mapped_column(String(40), nullable=False)  # e.g. "initial_access"
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)

    # MITRE mapping
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False)   # e.g. "T1566.001"
    technique_name: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g. "Phishing: Spearphishing Attachment"
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "initial_access"

    # Details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_host: Mapped[Optional[str]] = mapped_column(String(64))
    target_host: Mapped[Optional[str]] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    session: Mapped["Session"] = relationship(back_populates="attack_events")


# ---------------------------------------------------------------------------
# Log Entry (synthetic logs generated from attack events + noise)
# ---------------------------------------------------------------------------
class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=False)

    # Log metadata
    source: Mapped[str] = mapped_column(String(30), nullable=False)  # windows_event, linux_syslog, etc.
    event_id: Mapped[Optional[int]] = mapped_column(Integer)  # e.g. Windows Event ID 4625
    severity: Mapped[str] = mapped_column(String(10), default="info")
    category: Mapped[Optional[str]] = mapped_column(String(64))  # e.g. "authentication", "process_creation"

    # Content
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Context
    hostname: Mapped[Optional[str]] = mapped_column(String(64))
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45))
    username: Mapped[Optional[str]] = mapped_column(String(64))
    process_name: Mapped[Optional[str]] = mapped_column(String(128))

    # Is this a malicious log or benign noise?
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)

    # Link to the attack event that caused this log (null for noise)
    attack_event_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    session: Mapped["Session"] = relationship(back_populates="log_entries")


# ---------------------------------------------------------------------------
# Detection Rule (user-created Sigma rules)
# ---------------------------------------------------------------------------
class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[Optional[str]] = mapped_column(ForeignKey("sessions.id"), nullable=True)

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)  # Raw Sigma YAML content
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)  # Pre-loaded rules
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Stats
    true_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


# ---------------------------------------------------------------------------
# Alert (generated by detection engine)
# ---------------------------------------------------------------------------
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=False)

    # What triggered it
    rule_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # FK to detection rule
    detection_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "sigma" or "anomaly"

    # Alert details
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)

    # MITRE mapping
    technique_id: Mapped[Optional[str]] = mapped_column(String(16))
    tactic: Mapped[Optional[str]] = mapped_column(String(64))

    # Context
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45))
    hostname: Mapped[Optional[str]] = mapped_column(String(64))
    username: Mapped[Optional[str]] = mapped_column(String(64))
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)  # Triggering log entries

    # Triage
    triage_status: Mapped[str] = mapped_column(String(20), default="new")
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text)

    # Was the original event actually malicious? (for scoring)
    is_true_positive: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    triaged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Relationships
    session: Mapped["Session"] = relationship(back_populates="alerts")


# ---------------------------------------------------------------------------
# Report (user-written pentest or incident report)
# ---------------------------------------------------------------------------
class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)

    report_type: Mapped[str] = mapped_column(String(20), nullable=False)  # pentest / incident / debrief

    # Report content (structured JSON)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    executive_summary: Mapped[Optional[str]] = mapped_column(Text)
    sections: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)  # Flexible section content
    findings: Mapped[Optional[dict]] = mapped_column(JSON, default=list)  # List of findings/IOCs

    # Feedback
    quality_score: Mapped[Optional[float]] = mapped_column(Float)  # 0-100 AI-assessed score
    feedback: Mapped[Optional[dict]] = mapped_column(JSON)  # AI feedback per section

    # Export
    pdf_path: Mapped[Optional[str]] = mapped_column(String(256))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utcnow)

    # Relationships
    session: Mapped["Session"] = relationship(back_populates="reports")
    user: Mapped["User"] = relationship(back_populates="reports")


# ---------------------------------------------------------------------------
# Score (session performance)
# ---------------------------------------------------------------------------
class Score(Base):
    __tablename__ = "scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), unique=True, nullable=False)

    # Overall
    total_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    grade: Mapped[str] = mapped_column(String(20), default="pending")  # excellent/good/average/etc.

    # Breakdown
    detection_rate: Mapped[float] = mapped_column(Float, default=0.0)  # % of attacks detected
    mean_time_to_detect_sec: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    containment_score: Mapped[float] = mapped_column(Float, default=0.0)
    report_quality_score: Mapped[float] = mapped_column(Float, default=0.0)

    # MITRE coverage
    mitre_techniques_used: Mapped[int] = mapped_column(Integer, default=0)
    mitre_techniques_detected: Mapped[int] = mapped_column(Integer, default=0)
    mitre_coverage_pct: Mapped[float] = mapped_column(Float, default=0.0)

    # Meta
    details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)  # Full breakdown for debrief
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    session: Mapped["Session"] = relationship(back_populates="score")

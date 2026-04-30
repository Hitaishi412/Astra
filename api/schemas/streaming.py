"""
api/schemas/streaming.py
─────────────────────────
Pydantic schemas for streaming-related endpoints (logs, scores, mitre).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


# ════════════════════════════════════════════════════════════════════════════
# LOGS
# ════════════════════════════════════════════════════════════════════════════
class LogEntryResponse(BaseModel):
    """Response shape for a single log entry."""
    id: str
    session_id: str
    timestamp: datetime
    source: str
    event_id: Optional[int] = None
    severity: str
    category: Optional[str] = None
    message: str
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    is_malicious: bool = False

    model_config = {"from_attributes": True}


class LogStatsResponse(BaseModel):
    """Statistical summary of logs in a session."""
    session_id: str
    total: int
    by_source: dict[str, int]
    by_severity: dict[str, int]
    malicious_count: int
    benign_count: int


# ════════════════════════════════════════════════════════════════════════════
# SCORING
# ════════════════════════════════════════════════════════════════════════════
class ScoreResponse(BaseModel):
    """Response shape for a session score."""
    id: str
    session_id: str
    total_score: float
    grade: str
    detection_rate: float
    mean_time_to_detect_sec: float
    false_positive_rate: float
    containment_score: float
    report_quality_score: float
    mitre_techniques_used: int
    mitre_techniques_detected: int
    mitre_coverage_pct: float
    details: Optional[dict[str, Any]] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class LeaderboardEntry(BaseModel):
    """Single entry in the leaderboard."""
    rank: int
    session_id: str
    username: Optional[str] = None
    scenario_id: Optional[str] = None
    total_score: float
    grade: str
    mitre_coverage_pct: float


# ════════════════════════════════════════════════════════════════════════════
# MITRE
# ════════════════════════════════════════════════════════════════════════════
class TechniqueResponse(BaseModel):
    """Single ATT&CK technique."""
    id: str
    name: str
    description: Optional[str] = None
    tactics: list[str] = []
    platforms: list[str] = []
    url: Optional[str] = None


class CoverageResponse(BaseModel):
    """ATT&CK coverage for a session."""
    session_id: str
    techniques_used: list[str]              # IDs the attack engine ran
    techniques_detected: list[str]          # IDs the detection engine caught
    techniques_missed: list[str]            # used but not detected
    coverage_pct: float
    by_tactic: dict[str, dict[str, int]]    # tactic → {used, detected}


# ════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MESSAGE ENVELOPE  (mirrors streaming/channels.py:envelope)
# ════════════════════════════════════════════════════════════════════════════
class StreamMessage(BaseModel):
    """The envelope around every WebSocket message."""
    stream: str
    timestamp: datetime
    payload: dict[str, Any]

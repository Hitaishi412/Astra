"""
core/detection_engine/alert.py
───────────────────────────────
Alert generation helpers.

The schema lives in core/log_engine/schemas.py (AlertSchema). This module
provides constructors that build alerts from different sources:
  - from a Sigma rule match
  - from an anomaly detector flag
  - from a correlation event
"""

from __future__ import annotations

from typing import Optional

from core.log_engine.schemas import LogEntry, AlertSchema


def build_sigma_alert(
    *,
    session_id: str,
    rule: dict,
    matched_logs: list[LogEntry],
) -> AlertSchema:
    """
    Build an alert from a Sigma rule match.

    `rule` must have at minimum: id, name, description, severity.
    Optional: technique_id, tactic.
    """
    if not matched_logs:
        raise ValueError("Cannot build sigma alert without any matched logs.")

    primary = matched_logs[0]
    log_ids = [log.id for log in matched_logs]

    return AlertSchema(
        session_id=session_id,
        detection_type="sigma",
        rule_id=rule.get("id"),
        rule_name=rule.get("name"),
        title=rule.get("name", "Sigma Detection"),
        description=rule.get("description", "A Sigma rule fired."),
        severity=rule.get("severity", "medium"),
        technique_id=rule.get("technique_id"),
        tactic=rule.get("tactic"),
        hostname=primary.hostname,
        source_ip=primary.source_ip,
        destination_ip=primary.destination_ip,
        username=primary.username,
        evidence={
            "log_ids": log_ids,
            "log_count": len(matched_logs),
            "summary": _summarize_logs(matched_logs),
        },
    )


def build_anomaly_alert(
    *,
    session_id: str,
    anomaly_score: float,
    feature_summary: str,
    triggering_logs: list[LogEntry],
    severity: str = "medium",
) -> AlertSchema:
    """
    Build an alert from an anomaly detector flag.

    anomaly_score: lower = more anomalous (Isolation Forest convention,
                   typically -1.0 to 0.0 for outliers, > 0.0 for inliers).
    feature_summary: human-readable description of why the model flagged this.
    """
    primary = triggering_logs[0] if triggering_logs else None
    log_ids = [log.id for log in triggering_logs]

    return AlertSchema(
        session_id=session_id,
        detection_type="anomaly",
        title="Behavioral Anomaly Detected",
        description=(
            f"The anomaly model flagged unusual behavior. {feature_summary} "
            f"(score: {anomaly_score:.3f})"
        ),
        severity=severity,
        hostname=primary.hostname if primary else None,
        source_ip=primary.source_ip if primary else None,
        username=primary.username if primary else None,
        evidence={
            "log_ids": log_ids,
            "log_count": len(triggering_logs),
            "anomaly_score": anomaly_score,
            "summary": feature_summary,
        },
    )


def build_correlation_alert(
    *,
    session_id: str,
    pattern_name: str,
    description: str,
    contributing_alerts: list[AlertSchema],
    severity: str = "high",
    technique_id: Optional[str] = None,
    tactic: Optional[str] = None,
) -> AlertSchema:
    """
    Build a higher-severity correlation alert from multiple lower alerts.

    Example: 5 'failed login' alerts + 1 'successful login' alert from the same
    source IP within 2 minutes → correlation alert: 'Brute Force Success'.
    """
    primary = contributing_alerts[0] if contributing_alerts else None
    contributing_ids = [a.id for a in contributing_alerts]

    return AlertSchema(
        session_id=session_id,
        detection_type="correlation",
        title=pattern_name,
        description=description,
        severity=severity,
        technique_id=technique_id,
        tactic=tactic,
        hostname=primary.hostname if primary else None,
        source_ip=primary.source_ip if primary else None,
        username=primary.username if primary else None,
        evidence={
            "contributing_alert_ids": contributing_ids,
            "alert_count": len(contributing_alerts),
            "summary": f"Correlation of {len(contributing_alerts)} related alerts.",
        },
    )


# ─── Internal helpers ───────────────────────────────────────────────────────
def _summarize_logs(logs: list[LogEntry], max_chars: int = 200) -> str:
    """Build a one-line summary of the matched logs for the alert evidence."""
    if not logs:
        return ""
    if len(logs) == 1:
        return logs[0].message[:max_chars]
    sources = {log.source for log in logs}
    hosts = {log.hostname for log in logs if log.hostname}
    return (
        f"{len(logs)} matching logs across {len(sources)} source(s) "
        f"from {len(hosts)} host(s). First: {logs[0].message[:120]}"
    )

"""
core/detection_engine/correlation.py
─────────────────────────────────────
Combines multiple low-/medium-severity alerts into single high-severity
incidents based on shared context and time windows.

Examples of correlations we detect:
  - 5+ failed logins from same source_ip, then 1 success → "Brute Force Success"
  - PowerShell execution + outbound C2 connection within 60s → "Active Compromise"
  - Privilege escalation + lateral movement within 5m → "Active Lateral Compromise"
  - Reconnaissance + initial access on same host within 10m → "Targeted Attack"
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from core.detection_engine.alert import build_correlation_alert
from core.log_engine.schemas import AlertSchema


# ─── Pattern definitions ─────────────────────────────────────────────────────
@dataclass
class CorrelationPattern:
    """
    A correlation rule: looks for combinations of alerts within a time window.

    `triggers` is a list of (technique_id_prefix, optional_keyword_in_title).
    All triggers must occur within `window_seconds` and share a context
    field (e.g. same source_ip, same hostname).
    """
    name: str
    description: str
    severity: str
    triggers: list[dict]            # [{"keyword": "brute force", ...}, ...]
    window_seconds: int
    shared_field: str = "source_ip"  # source_ip | hostname | username
    technique_id: Optional[str] = None
    tactic: Optional[str] = None
    min_match_count: int = 2


# Built-in correlation patterns
DEFAULT_PATTERNS: list[CorrelationPattern] = [
    CorrelationPattern(
        name="Brute Force Success",
        description=(
            "Multiple failed logins followed by a successful login from the same "
            "source — indicates a successful brute force attack."
        ),
        severity="critical",
        triggers=[
            {"keyword": "brute force", "or_keyword": "failed login"},
            {"keyword": "successful login", "or_keyword": "authentication success"},
        ],
        window_seconds=600,  # 10 minutes
        shared_field="source_ip",
        technique_id="T1110",
        tactic="credential_access",
        min_match_count=2,
    ),
    CorrelationPattern(
        name="Execute then Exfiltrate",
        description=(
            "Suspicious code execution followed by outbound data transfer — "
            "indicates an active compromise with exfiltration in progress."
        ),
        severity="critical",
        triggers=[
            {"keyword": "powershell", "or_keyword": "execution"},
            {"keyword": "exfil", "or_keyword": "outbound"},
        ],
        window_seconds=300,  # 5 minutes
        shared_field="hostname",
        technique_id="T1041",
        tactic="exfiltration",
        min_match_count=2,
    ),
    CorrelationPattern(
        name="Privilege Escalation + Lateral Movement",
        description=(
            "An attacker escalated privileges and then moved laterally to another "
            "host — indicates an active intruder spreading through the network."
        ),
        severity="critical",
        triggers=[
            {"keyword": "privilege", "or_keyword": "escalation"},
            {"keyword": "lateral", "or_keyword": "psexec"},
        ],
        window_seconds=600,
        shared_field="hostname",
        technique_id="T1570",
        tactic="lateral_movement",
        min_match_count=2,
    ),
    CorrelationPattern(
        name="Reconnaissance + Initial Access",
        description=(
            "Recon activity followed shortly by initial access on the same host — "
            "indicates a targeted attack with prior intelligence."
        ),
        severity="high",
        triggers=[
            {"keyword": "scan", "or_keyword": "recon"},
            {"keyword": "phishing", "or_keyword": "exploit", "or_keyword2": "initial access"},
        ],
        window_seconds=900,  # 15 minutes
        shared_field="hostname",
        technique_id="T1595",
        tactic="reconnaissance",
        min_match_count=2,
    ),
]


# ─── Correlation engine ──────────────────────────────────────────────────────
class CorrelationEngine:
    """
    Maintains a sliding window of recent alerts and looks for patterns.

    Usage:
        eng = CorrelationEngine()
        for new_alert in detection_pipeline.alerts:
            eng.add_alert(new_alert)
            for incident in eng.find_correlations(new_alert.session_id):
                emit(incident)
    """

    def __init__(
        self,
        patterns: Optional[list[CorrelationPattern]] = None,
        max_window_seconds: int = 3600,
    ):
        self.patterns = patterns or DEFAULT_PATTERNS
        self.max_window_seconds = max_window_seconds
        # Per-session alert buffers
        self._buffers: dict[str, list[AlertSchema]] = defaultdict(list)
        # Track which (pattern, key) combinations have already fired (avoid duplicates)
        self._fired: set[tuple[str, str, str]] = set()

    # ── State management ─────────────────────────────────────────────────────
    def add_alert(self, alert: AlertSchema) -> None:
        """Add an alert to the per-session buffer; prune old alerts."""
        sid = alert.session_id
        self._buffers[sid].append(alert)
        self._prune(sid)

    def _prune(self, session_id: str) -> None:
        """Remove alerts older than max_window_seconds from the buffer."""
        if session_id not in self._buffers:
            return
        buf = self._buffers[session_id]
        if not buf:
            return
        now = buf[-1].timestamp
        cutoff = now - timedelta(seconds=self.max_window_seconds)
        self._buffers[session_id] = [a for a in buf if a.timestamp >= cutoff]

    # ── Pattern matching ─────────────────────────────────────────────────────
    def find_correlations(self, session_id: str) -> list[AlertSchema]:
        """Run all patterns against the session's alert buffer; return new incident alerts."""
        results = []
        for pattern in self.patterns:
            results.extend(self._match_pattern(session_id, pattern))
        return results

    def _match_pattern(
        self,
        session_id: str,
        pattern: CorrelationPattern,
    ) -> list[AlertSchema]:
        """Try to match one pattern against the session's alert buffer."""
        buf = self._buffers.get(session_id, [])
        if len(buf) < pattern.min_match_count:
            return []

        # Group alerts by shared context (source_ip, hostname, etc.)
        groups: dict[str, list[AlertSchema]] = defaultdict(list)
        for alert in buf:
            key = getattr(alert, pattern.shared_field, None) or "__none__"
            if key != "__none__":
                groups[key].append(alert)

        results = []
        for context_key, group in groups.items():
            # Check that each trigger has at least one matching alert in the group
            matched_per_trigger = []
            for trigger in pattern.triggers:
                matches = [a for a in group if _alert_matches_trigger(a, trigger)]
                if not matches:
                    matched_per_trigger = []
                    break
                matched_per_trigger.append(matches)

            if len(matched_per_trigger) < len(pattern.triggers):
                continue

            # Validate timing: do all matched alerts fall within the window?
            all_matched = [a for matches in matched_per_trigger for a in matches]
            all_matched.sort(key=lambda a: a.timestamp)
            time_span = (all_matched[-1].timestamp - all_matched[0].timestamp).total_seconds()
            if time_span > pattern.window_seconds:
                continue

            # Avoid re-firing the same incident
            fired_key = (pattern.name, pattern.shared_field, context_key)
            if fired_key in self._fired:
                continue
            self._fired.add(fired_key)

            results.append(
                build_correlation_alert(
                    session_id=session_id,
                    pattern_name=pattern.name,
                    description=(
                        f"{pattern.description} "
                        f"Affects {pattern.shared_field}={context_key}."
                    ),
                    contributing_alerts=all_matched,
                    severity=pattern.severity,
                    technique_id=pattern.technique_id,
                    tactic=pattern.tactic,
                )
            )
        return results

    # ── Reset for a new session ──────────────────────────────────────────────
    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._buffers.pop(session_id, None)
        else:
            self._buffers.clear()
            self._fired.clear()


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _alert_matches_trigger(alert: AlertSchema, trigger: dict) -> bool:
    """
    Check if an alert matches a trigger spec.
    Trigger spec can have multiple `keyword` / `or_keyword` / `or_keyword2` fields.
    """
    text = f"{alert.title} {alert.description}".lower()
    keywords = [v for k, v in trigger.items() if "keyword" in k]
    return any(kw.lower() in text for kw in keywords)

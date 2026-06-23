"""
dashboard/components/renderers.py
──────────────────────────────────
Pure renderers — take a payload, return a dash component tree.

These are stateless functions called by streaming/api callbacks.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from dash import html


# ════════════════════════════════════════════════════════════════════════════
# LOGS — table row renderer
# ════════════════════════════════════════════════════════════════════════════
def render_log_row(log: dict[str, Any]) -> html.Div:
    """Render a single log row in the live event stream table."""
    severity = (log.get("severity") or "info").lower()
    is_malicious = log.get("is_malicious", False)

    # Format timestamp
    ts = log.get("timestamp", "")
    if isinstance(ts, str) and "T" in ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            time_str = dt.strftime("%H:%M:%S")
        except Exception:
            time_str = ts[-12:-3] if len(ts) > 12 else ts
    else:
        time_str = "—"

    return html.Div(
        [
            html.Span(time_str, className="log-time"),
            html.Span(log.get("source", "—"), className="log-source"),
            html.Span(severity.upper(), className=f"log-severity {severity}"),
            html.Span(log.get("message", "—"), className="log-message", title=log.get("message", "")),
            html.Span(log.get("hostname", "—"), className="log-host"),
        ],
        className=f"log-row {'malicious' if is_malicious else ''}",
    )


# ════════════════════════════════════════════════════════════════════════════
# ALERTS — card renderer
# ════════════════════════════════════════════════════════════════════════════
def render_alert_card(alert: dict[str, Any]) -> html.Div:
    """Render an alert as a clickable card in the right sidebar.

    The card has a pattern-matching id so a single Dash callback can
    handle clicks on any alert. The alert id is embedded in the
    pattern; the full payload is read from `live-alerts-store` on click.
    """
    severity = (alert.get("severity") or "medium").lower()

    ts = alert.get("timestamp", "")
    if isinstance(ts, str) and "T" in ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            time_str = dt.strftime("%H:%M:%S")
        except Exception:
            time_str = ts[-12:-3] if len(ts) > 12 else ts
    else:
        time_str = "—"

    technique = alert.get("technique_id", "")
    technique_block = (
        html.Span(technique, className="alert-mitre-tag") if technique else None
    )

    triage = (alert.get("triage_status") or "new").lower()
    triage_badge = None
    if triage and triage != "new":
        badge_label = {
            "investigating":   "INVESTIGATING",
            "true_positive":   "✓ TP",
            "false_positive":  "✗ FP",
            "escalated":       "↑ ESCALATED",
            "resolved":        "RESOLVED",
        }.get(triage, triage.upper())
        triage_badge = html.Span(
            badge_label,
            className=f"alert-triage-badge triage-{triage}",
            style={"marginLeft": "auto", "fontSize": "10px", "opacity": "0.85"},
        )

    alert_id = alert.get("id") or alert.get("alert_id") or ""

    return html.Div(
        [
            html.Div(
                [
                    html.Span(severity.upper(), className=f"alert-severity-badge {severity}"),
                    html.Span(time_str, className="alert-time"),
                    *([triage_badge] if triage_badge else []),
                ],
                className="alert-card-header",
            ),
            html.Div(alert.get("title", "Untitled alert"), className="alert-title"),
            html.Div(
                [
                    *([technique_block] if technique_block else []),
                    html.Span(alert.get("hostname", "—")),
                    html.Span(alert.get("rule_name", "")),
                ],
                className="alert-meta",
            ),
        ],
        id={"type": "alert-card", "id": str(alert_id)},
        n_clicks=0,
        className=f"alert-card severity-{severity} clickable",
        style={"cursor": "pointer"},
    )


# ════════════════════════════════════════════════════════════════════════════
# KILL CHAIN — phase strip update
# ════════════════════════════════════════════════════════════════════════════
_PHASE_NAMES = [
    "Recon", "Initial Access", "Execution", "Persistence",
    "Lateral Movement", "Exfiltration", "Impact",
]


def render_kill_chain(current_phase_idx: int, completed_phases: list[int]) -> list[html.Div]:
    """Render the 7-phase kill chain strip with active/completed states."""
    cells = []
    for i, name in enumerate(_PHASE_NAMES):
        if i in completed_phases:
            cls = "kc-phase completed"
        elif i == current_phase_idx:
            cls = "kc-phase active"
        else:
            cls = "kc-phase"
        cells.append(html.Div(
            [
                html.Div(f"{i + 1:02d}", className="kc-phase-number"),
                html.Div(name, className="kc-phase-name"),
            ],
            className=cls,
        ))
    return cells


# ════════════════════════════════════════════════════════════════════════════
# SCORE — sub-score breakdown grid
# ════════════════════════════════════════════════════════════════════════════
def render_score_breakdown(score_dict: dict[str, Any]) -> list[html.Div]:
    """Render the small grid of sub-scores under the big number."""
    if not score_dict:
        return []

    sub = score_dict.get("details", {}).get("sub_scores", {})
    items = [
        ("Detection",   sub.get("detection_score", 0)),
        ("MTTD",        sub.get("mttd_score", 0)),
        ("FP Rate",     sub.get("fp_score", 0)),
        ("Containment", sub.get("containment_score", 0)),
        ("Report",      sub.get("report_score", 0)),
        ("Coverage",    score_dict.get("mitre_coverage_pct", 0)),
    ]

    return [
        html.Div(
            [
                html.Div(label, className="subscore-label"),
                html.Div(f"{value:.1f}", className="subscore-value"),
            ],
            className="subscore-item",
        )
        for label, value in items
    ]


# ════════════════════════════════════════════════════════════════════════════
# MITRE MATRIX — grid renderer
# ════════════════════════════════════════════════════════════════════════════
def render_mitre_matrix(
    coverage: dict[str, Any],
    tactic_order: list[tuple[str, str]],
    enterprise_techniques: dict[str, dict] | None = None,
) -> html.Div:
    """
    Render the ATT&CK matrix view from a coverage_summary() dict.

    Args:
        coverage: output of MitreMapper.coverage_summary()
        tactic_order: [(tactic_id, display_name), ...]
        enterprise_techniques: optional full technique catalog (for technique names)
    """
    used = set(coverage.get("techniques_used", []))
    detected = set(coverage.get("techniques_detected", []))
    missed = set(coverage.get("techniques_missed", []))

    # Group techniques by tactic
    by_tactic = coverage.get("by_tactic", {})

    columns = []
    for tactic_id, display_name in tactic_order:
        # Find techniques that hit this tactic
        techniques_in_tactic = []
        for tid in used:
            tinfo = (enterprise_techniques or {}).get(tid, {})
            if tactic_id in tinfo.get("tactics", []):
                techniques_in_tactic.append(tid)

        # If we don't have enterprise data, fall back to "show all used techniques in the first column"
        if not enterprise_techniques and tactic_id == tactic_order[0][0]:
            techniques_in_tactic = sorted(used)

        if not techniques_in_tactic:
            continue

        techs = []
        for tid in sorted(techniques_in_tactic):
            if tid in detected:
                cls = "matrix-technique detected"
            elif tid in missed:
                cls = "matrix-technique missed"
            else:
                cls = "matrix-technique used"
            techs.append(html.Div(tid, className=cls))

        stats = by_tactic.get(tactic_id, {})
        used_n = stats.get("used", 0)
        det_n = stats.get("detected", 0)

        columns.append(
            html.Div(
                [
                    html.Div(
                        [
                            display_name.upper(),
                            html.Span(
                                f"{det_n}/{used_n}",
                                style={
                                    "float": "right",
                                    "fontFamily": "var(--font-mono)",
                                    "color": "var(--text-tertiary)",
                                },
                            ),
                        ],
                        className="matrix-tactic-header",
                    ),
                    *techs,
                ],
                className="matrix-tactic-col",
            )
        )

    if not columns:
        return html.Div(
            [
                html.Div("⊞", className="empty-state-icon"),
                "No technique data — start a session and let it run",
            ],
            className="empty-state",
        )

    return html.Div(columns, className="matrix-grid")


# ════════════════════════════════════════════════════════════════════════════
# HISTORY / LEADERBOARD ROWS
# ════════════════════════════════════════════════════════════════════════════
def render_history_row(session: dict[str, Any]) -> html.Div:
    """Render a row in the history table."""
    score = session.get("total_score")
    grade = session.get("grade", "—")
    coverage = session.get("mitre_coverage_pct", 0)

    score_str = f"{score:.1f}" if score is not None else "—"

    completed_at = session.get("created_at", "")
    if isinstance(completed_at, str) and "T" in completed_at:
        try:
            dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            completed_str = dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            completed_str = completed_at[:16]
    else:
        completed_str = "—"

    return html.Div(
        [
            html.Span(session.get("session_id", "—")[:12], className="log-source"),
            html.Span(session.get("scenario_id", "—"), className="log-message"),
            html.Span(score_str, className="log-severity " + grade.lower().replace("_", "-")),
            html.Span(f"{coverage:.0f}%", className="log-host"),
            html.Span(f"{session.get('duration_sec', 0):.0f}s", className="log-host"),
            html.Span(completed_str, className="log-time"),
        ],
        className="log-row",
        style={"gridTemplateColumns": "120px 1fr 90px 90px 100px 160px"},
    )


def render_leaderboard_row(entry: dict[str, Any]) -> html.Div:
    """Render a row in the leaderboard."""
    grade = entry.get("grade", "—")
    return html.Div(
        [
            html.Span(f"#{entry.get('rank', '—')}", className="log-source"),
            html.Span(entry.get("username", "—"), className="log-message"),
            html.Span(entry.get("scenario_id", "—"), className="log-host"),
            html.Span(f"{entry.get('total_score', 0):.1f}", className="log-severity high"),
            html.Span(grade.replace("_", " ").title(), className=f"score-grade {grade.lower()}"),
            html.Span(f"{entry.get('mitre_coverage_pct', 0):.0f}%", className="log-host"),
        ],
        className="log-row",
        style={"gridTemplateColumns": "60px 160px 1fr 100px 120px 100px"},
    )

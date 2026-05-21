"""
dashboard/callbacks/streaming.py
─────────────────────────────────
Callbacks for the Live Session page — launches a session and updates the UI
live as logs/alerts come in.

Architecture note:
  Dash callbacks can't hold long-running websockets directly. So we use a
  background worker (started when the user clicks "Launch") that subscribes
  to the streaming backend and pushes events into a thread-safe deque per
  session. The dcc.Interval ('live-tick') fires every second to drain the
  deque into the dcc.Store, which triggers the rendering callbacks.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections import deque
from typing import Any, Optional

import httpx
from dash import ALL, Input, Output, State, ctx as dash_ctx, dcc, html, no_update

from dashboard.callbacks._auth import auth_headers
from dashboard.components.renderers import (
    render_alert_card,
    render_kill_chain,
    render_log_row,
    render_score_breakdown,
)


logger = logging.getLogger("astra.dashboard.streaming")


# Maps the dashboard's "mode" picker (mode_picker.py) to the API's `role` field
# (api/schemas/session.py: SessionCreate uses pattern ^(red_team|blue_team|full_spectrum)$).
_MODE_TO_ROLE = {
    "soc":       "blue_team",
    "pentester": "red_team",
    "purple":    "full_spectrum",
}

# Maps the dashboard's difficulty values to the API's accepted set. The
# dashboard exposes "easy" for friendlier copy, but SessionCreate only
# accepts beginner/medium/hard/expert. Keep the others identity-mapped.
_DIFFICULTY_MAP = {
    "easy":     "beginner",
    "beginner": "beginner",
    "medium":   "medium",
    "hard":     "hard",
    "expert":   "expert",
}


# ════════════════════════════════════════════════════════════════════════════
# THREAD-SAFE EVENT BUFFER per session
# ════════════════════════════════════════════════════════════════════════════
class _SessionBuffer:
    """Bounded thread-safe buffers for logs / alerts / status / scores."""
    def __init__(self, maxlen: int = 500):
        self.logs: deque = deque(maxlen=maxlen)
        self.alerts: deque = deque(maxlen=200)
        self.attack_status: dict[str, Any] = {}
        self.score: dict[str, Any] = {}
        self.lock = threading.Lock()
        # The OS thread that runs the asyncio loop. Not an asyncio.Task.
        self.worker_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()


_buffers: dict[str, _SessionBuffer] = {}
_buffers_lock = threading.Lock()


def _get_buffer(session_id: str) -> _SessionBuffer:
    with _buffers_lock:
        if session_id not in _buffers:
            _buffers[session_id] = _SessionBuffer()
        return _buffers[session_id]


def _drop_buffer(session_id: str) -> None:
    """Stop the worker thread (if running) and remove the buffer."""
    with _buffers_lock:
        buf = _buffers.pop(session_id, None)
    if buf is not None:
        buf.stop_event.set()


# ════════════════════════════════════════════════════════════════════════════
# BACKGROUND SUBSCRIBER — one thread per active session
# ════════════════════════════════════════════════════════════════════════════
def _start_subscriber(session_id: str):
    """Spawn a thread that subscribes to streaming for this session."""
    buf = _get_buffer(session_id)
    if buf.worker_thread is not None and buf.worker_thread.is_alive():
        return  # already running

    def _run():
        # Each thread needs its own event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_subscribe_loop(session_id, buf))
        except Exception as e:
            logger.exception(f"subscriber thread crashed for session={session_id}: {e}")
        finally:
            try:
                loop.close()
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True, name=f"astra-sub-{session_id[:8]}")
    t.start()
    buf.worker_thread = t


async def _subscribe_loop(session_id: str, buf: _SessionBuffer):
    """Subscribe to all relevant streams for this session and fan out into the buffer."""
    try:
        from streaming.backend import get_backend
        from streaming.channels import StreamType, channel_for, deserialize
    except ImportError:
        logger.warning("streaming module not importable from dashboard")
        return

    backend = get_backend()
    channels = [
        channel_for(session_id, StreamType.LOGS),
        channel_for(session_id, StreamType.ALERTS),
        channel_for(session_id, StreamType.ATTACK_STATUS),
        channel_for(session_id, StreamType.SCORES),
    ]

    try:
        async for channel, raw in backend.subscribe(*channels):
            if buf.stop_event.is_set():
                break
            try:
                msg = deserialize(raw)
            except Exception:
                continue
            stream_name = msg.get("stream") or channel.split(":")[-1]
            payload = msg.get("payload", {})
            with buf.lock:
                if stream_name == "logs":
                    buf.logs.append(payload)
                elif stream_name == "alerts":
                    buf.alerts.append(payload)
                elif stream_name == "attack_status":
                    buf.attack_status = payload
                elif stream_name == "scores":
                    buf.score = payload
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.exception(f"subscriber crashed for session={session_id}: {e}")


# ════════════════════════════════════════════════════════════════════════════
# CALLBACKS
# ════════════════════════════════════════════════════════════════════════════
def register(app):
    """Register live-session callbacks."""

    # ── Launch button → start session via API ───────────────────────────
    # Two-step flow:
    #   1. POST /sessions  → create a DB row, get a real session_id
    #   2. POST /attacks/run/<scenario>  → kick off the background driver
    @app.callback(
        Output("active-session", "data"),
        Output("live-tick", "disabled"),
        Output("launch-status", "children"),
        Output("live-main-area", "children"),
        Input("launch-button", "n_clicks"),
        State("launcher-scenario", "value"),
        State("launcher-difficulty", "value"),
        State("active-mode", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
        prevent_initial_call=True,
    )
    def launch_session(n_clicks, scenario, difficulty, mode, api_base, token):
        if not n_clicks or not scenario:
            return no_update, no_update, no_update, no_update

        # Map dashboard mode → API role
        role = _MODE_TO_ROLE.get(mode or "soc", "blue_team")
        # Map dashboard difficulty → API difficulty (the dashboard exposes
        # "easy" but the SessionCreate schema only accepts beginner/medium/hard/expert)
        api_difficulty = _DIFFICULTY_MAP.get(difficulty, "medium")

        # ── Step 1: create the session in the DB ─────────────────────────
        try:
            with httpx.Client(timeout=5.0, headers=auth_headers(token)) as client:
                resp = client.post(
                    f"{api_base}/sessions",
                    json={
                        "username":    "demo",
                        "scenario_id": scenario,
                        "role":        role,
                        "difficulty":  api_difficulty,
                    },
                )
            if resp.status_code not in (200, 201):
                detail = resp.text[:200]
                return no_update, no_update, html.Div(
                    f"⚠ Failed to create session ({resp.status_code}): {detail}",
                    style={"color": "var(--severity-critical)", "marginTop": "12px"},
                ), no_update
            session_id = resp.json()["id"]
        except Exception as e:
            return no_update, no_update, html.Div(
                f"⚠ Failed to create session: {e}",
                style={"color": "var(--severity-critical)", "marginTop": "12px"},
            ), no_update

        # Start the subscriber BEFORE the simulation starts — so we don't miss events
        _start_subscriber(session_id)

        # ── Step 2: kick off the background attack driver ────────────────
        try:
            with httpx.Client(timeout=5.0, headers=auth_headers(token)) as client:
                run_resp = client.post(
                    f"{api_base}/attacks/run/{scenario}",
                    params={"session_id": session_id, "difficulty": api_difficulty},
                )
            if run_resp.status_code not in (200, 201, 202):
                _drop_buffer(session_id)
                detail = run_resp.text[:200]
                return no_update, no_update, html.Div(
                    f"⚠ Failed to launch ({run_resp.status_code}): {detail}",
                    style={"color": "var(--severity-critical)", "marginTop": "12px"},
                ), no_update
        except Exception as e:
            _drop_buffer(session_id)
            return no_update, no_update, html.Div(
                f"⚠ Failed to launch: {e}",
                style={"color": "var(--severity-critical)", "marginTop": "12px"},
            ), no_update

        # Replace launcher form with the live grid
        live_grid = _build_live_grid(session_id, scenario, api_difficulty)
        return session_id, False, html.Div(
            f"✓ Session {session_id[:8]} launched — {scenario} / {api_difficulty}",
            style={"color": "var(--status-good)", "marginTop": "12px"},
        ), live_grid

    # ── Live tick → drain buffer into Stores ────────────────────────────
    @app.callback(
        Output("live-logs-store", "data"),
        Output("live-alerts-store", "data"),
        Output("live-stats-store", "data"),
        Input("live-tick", "n_intervals"),
        State("active-session", "data"),
        State("live-stats-store", "data"),
        prevent_initial_call=True,
    )
    def drain_buffer(_n, session_id, prev_stats):
        if not session_id:
            return no_update, no_update, no_update
        buf = _get_buffer(session_id)
        with buf.lock:
            logs = list(buf.logs)
            alerts = list(buf.alerts)
            attack_status = dict(buf.attack_status)
            score = dict(buf.score)

        prev = prev_stats or {}
        # Build stats
        coverage = score.get("mitre_coverage_pct", prev.get("coverage_pct", 0)) if score else prev.get("coverage_pct", 0)
        score_value = score.get("total_score", prev.get("score", 0)) if score else prev.get("score", 0)

        # Phase tracking from attack_status
        phase_name = (attack_status.get("current_phase") or "").lower()
        phase_idx = _phase_to_index(phase_name)
        completed = attack_status.get("phases_completed", [])
        completed_idx = [_phase_to_index(p.lower()) for p in completed if _phase_to_index(p.lower()) >= 0]

        stats = {
            "logs_count": len(logs),
            "alerts_count": len(alerts),
            "coverage_pct": coverage,
            "score": score_value,
            "current_phase": phase_idx,
            "completed_phases": completed_idx,
            "score_full": score,
            "session_state": (attack_status.get("state") or "").lower(),
        }
        return logs, alerts, stats

    # ── Render log table ─────────────────────────────────────────────────
    @app.callback(
        Output("log-stream-body", "children"),
        Output("log-stream-count", "children"),
        Input("live-logs-store", "data"),
    )
    def render_logs(logs):
        if not logs:
            return [
                html.Div(
                    [html.Div("⌂", className="empty-state-icon"), "Waiting for log stream..."],
                    className="empty-state",
                )
            ], "0 events"
        # Show newest first, cap at 200 in the DOM for perf
        recent = list(reversed(logs))[:200]
        return [render_log_row(l) for l in recent], f"{len(logs)} events"

    # ── Render alerts feed ───────────────────────────────────────────────
    @app.callback(
        Output("alerts-stream", "children"),
        Output("alerts-count", "children"),
        Input("live-alerts-store", "data"),
    )
    def render_alerts(alerts):
        if not alerts:
            return [
                html.Div(
                    [html.Div("◇", className="empty-state-icon"), "No alerts yet"],
                    className="empty-state",
                )
            ], "0"
        recent = list(reversed(alerts))[:50]
        return [render_alert_card(a) for a in recent], str(len(alerts))

    # ── Update stat blocks + kill chain + score panel ───────────────────
    @app.callback(
        Output("stat-logs", "children"),
        Output("stat-alerts", "children"),
        Output("stat-coverage", "children"),
        Output("stat-score", "children"),
        Output("kill-chain-strip", "children"),
        Output("score-number", "children"),
        Output("score-grade", "children"),
        Output("score-grade", "className"),
        Output("score-subscores", "children"),
        Input("live-stats-store", "data"),
    )
    def render_stats(stats):
        if not stats:
            return ("0", "0", "0%", "0", no_update, "0", "—", "score-grade", [])

        kc = render_kill_chain(stats.get("current_phase", -1), stats.get("completed_phases", []))

        score_full = stats.get("score_full") or {}
        grade = score_full.get("grade", "—")
        score_val = stats.get("score", 0)

        return (
            str(stats.get("logs_count", 0)),
            str(stats.get("alerts_count", 0)),
            f"{stats.get('coverage_pct', 0):.0f}%",
            f"{score_val:.0f}",
            kc,
            f"{score_val:.0f}",
            grade.upper().replace("_", " "),
            f"score-grade {grade.lower()}",
            render_score_breakdown(score_full),
        )

    # ── Coverage donut + score sparkline (live) ──────────────────────────
    @app.callback(
        Output("stat-coverage-donut", "figure"),
        Output("score-sparkline-chart", "figure"),
        Input("live-stats-store", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
        State("active-mode", "data"),
    )
    def render_donut_and_sparkline(stats, api_base, mode, token):
        from dashboard.components.charts import coverage_donut, score_sparkline, empty_chart
        if not stats:
            return empty_chart("0%", height=140), empty_chart("", height=60)
        coverage_pct = float(stats.get("coverage_pct", 0))
        score_full = stats.get("score_full") or {}
        mitre = score_full.get("details", {}).get("mitre", {})
        detected = mitre.get("techniques_detected", 0) if isinstance(mitre, dict) else 0
        used     = mitre.get("techniques_used", 0)     if isinstance(mitre, dict) else 0
        donut = coverage_donut(coverage_pct, detected=detected, total=used)

        # For sparkline, fetch recent scores (cheap polling)
        history = []
        try:
            with httpx.Client(timeout=2.0, headers=auth_headers(token)) as client:
                r = client.get(f"{api_base}/scoring/leaderboard?limit=10")
                r.raise_for_status()
                history = [e.get("total_score", 0) for e in reversed(r.json())]
        except Exception:
            pass
        spark = score_sparkline(history, current=stats.get("score"))
        return donut, spark

    # ── Abort button ─────────────────────────────────────────────────────
    @app.callback(
        Output("active-session", "data", allow_duplicate=True),
        Output("live-tick", "disabled", allow_duplicate=True),
        Output("live-main-area", "children", allow_duplicate=True),
        Input("abort-button", "n_clicks"),
        State("active-session", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
        State("active-mode", "data"),
        prevent_initial_call=True,
    )
    def abort_session(n_clicks, session_id, api_base, mode, token):
        if not n_clicks or not session_id:
            return no_update, no_update, no_update
        # Tell backend to stop
        try:
            with httpx.Client(timeout=3.0, headers=auth_headers(token)) as client:
                client.post(f"{api_base}/attacks/abort", json={"session_id": session_id})
        except Exception:
            pass
        # Stop the subscriber thread
        _drop_buffer(session_id)
        # Reset to launcher form
        from dashboard.layouts.live_session import _launcher_form
        from dashboard.layouts.mode_picker import MODES
        _mode_obj = next((m for m in MODES if m["id"] == (mode or "soc")), MODES[0])
        return None, True, _launcher_form(_mode_obj)

    # ── Alert click → open detail/triage panel ──────────────────────────
    # Pattern-matching listens for clicks on any rendered alert card.

    @app.callback(
        Output("selected-alert-id", "data"),
        Output("triage-panel-body", "children"),
        Output("triage-panel-meta", "children"),
        Input({"type": "alert-card", "id": ALL}, "n_clicks"),
        State("live-alerts-store", "data"),
        prevent_initial_call=True,
    )
    def open_triage_panel(_clicks, alerts):
        # Filter out the case where ALL clicks are 0 (initial render, layout change)
        if not _clicks or not any(c for c in _clicks if c):
            return no_update, no_update, no_update
        if not dash_ctx.triggered_id:
            return no_update, no_update, no_update
        clicked_id = dash_ctx.triggered_id.get("id")
        if not clicked_id or not alerts:
            return no_update, no_update, no_update

        alert = next(
            (a for a in alerts if str(a.get("id") or a.get("alert_id") or "") == str(clicked_id)),
            None,
        )
        if alert is None:
            return no_update, no_update, no_update

        return clicked_id, _render_triage_body(alert), f"#{clicked_id[:8]}"

    # ── Triage submit ──────────────────────────────────────────────────
    @app.callback(
        Output("triage-feedback", "data"),
        Input("triage-tp-button", "n_clicks"),
        Input("triage-fp-button", "n_clicks"),
        Input("triage-escalate-button", "n_clicks"),
        State("selected-alert-id", "data"),
        State("triage-notes-input", "value"),
        State("api-base", "data"),
        State("auth-token", "data"),
        prevent_initial_call=True,
    )
    def submit_triage(_tp, _fp, _esc, alert_id, notes, api_base, token):
        if not alert_id or not dash_ctx.triggered_id:
            return no_update
        clicked = dash_ctx.triggered_id
        decision = {
            "triage-tp-button":       ("true_positive",  True),
            "triage-fp-button":       ("false_positive", False),
            "triage-escalate-button": ("escalated",      None),
        }.get(clicked)
        if decision is None:
            return no_update
        triage_status, is_tp = decision

        body = {
            "triage_status":   triage_status,
            "analyst_notes":   notes or None,
        }
        if is_tp is not None:
            body["is_true_positive"] = is_tp

        try:
            with httpx.Client(timeout=4.0, headers=auth_headers(token)) as client:
                resp = client.patch(f"{api_base}/alerts/{alert_id}/triage", json=body)
            if resp.status_code in (200, 201):
                return f"✓ Triaged as {triage_status.replace('_', ' ')}"
            return f"⚠ Triage failed ({resp.status_code})"
        except Exception as e:
            return f"⚠ Triage failed: {e}"

    # ── Display the triage feedback into the panel ─────────────────────
    @app.callback(
        Output("triage-feedback-text", "children"),
        Input("triage-feedback", "data"),
        prevent_initial_call=True,
    )
    def show_triage_feedback(msg):
        return msg or ""

    # ── End & Write Report → navigate to report writer ───────────────────
    @app.callback(
        Output("url", "pathname", allow_duplicate=True),
        Input("end-and-report-button", "n_clicks"),
        State("active-session", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
        prevent_initial_call=True,
    )
    def end_and_write_report(n_clicks, session_id, api_base, token):
        if not n_clicks or not session_id:
            return no_update
        # Stop the running session — best-effort
        try:
            with httpx.Client(timeout=3.0, headers=auth_headers(token)) as client:
                client.post(f"{api_base}/attacks/abort", json={"session_id": session_id})
        except Exception:
            pass
        return f"/report/{session_id}"

    # ── Auto-redirect when session reaches "completed" ───────────────────
    # The driver publishes attack_status with state="completed" when the
    # finaliser finishes. We watch the stats store; once the score is
    # finalised (preview=False, or we see state in the buffer), redirect.
    @app.callback(
        Output("url", "pathname", allow_duplicate=True),
        Input("live-stats-store", "data"),
        State("active-session", "data"),
        State("url", "pathname"),
        prevent_initial_call=True,
    )
    def auto_redirect_on_complete(stats, session_id, current_path):
        if not session_id or not stats:
            return no_update
        # If we're already off the live page, don't fight the user
        if current_path and not current_path.startswith("/live"):
            return no_update
        if (stats.get("session_state") or "").lower() == "completed":
            return f"/report/{session_id}"
        return no_update


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════
def _phase_to_index(phase_name: str) -> int:
    """Map phase name strings to kill chain strip indices (0-6)."""
    mapping = {
        "reconnaissance": 0, "recon": 0,
        "delivery": 1, "initial_access": 1, "initial-access": 1,
        "exploitation": 2, "execution": 2,
        "installation": 3, "persistence": 3,
        "command_and_control": 4, "lateral_movement": 4, "lateral-movement": 4,
        "actions_on_objectives": 5, "exfiltration": 5,
        "impact": 6,
    }
    return mapping.get(phase_name.lower(), -1)


def _build_live_grid(session_id: str, scenario: str, difficulty: str):
    """Build the live grid that replaces the launcher form once a session starts."""
    from dashboard.layouts.live_session import _alerts_card, _log_stream_card, _score_panel

    return html.Div(
        [
            # Stores for triage panel state
            dcc.Store(id="selected-alert-id", data=None),
            dcc.Store(id="triage-feedback", data=""),
            # Location is the global one — used for redirect to report writer.
            # We avoid creating a new dcc.Location here; the app already has one.
            html.Div(
                [
                    html.Span(
                        f"▶ {scenario} / {difficulty} / {session_id[:8]}",
                        style={
                            "fontFamily": "var(--font-mono)",
                            "color": "var(--text-secondary)",
                            "fontSize": "13px",
                        },
                    ),
                    html.Div(
                        [
                            html.Button(
                                "■ Abort Session",
                                id="abort-button",
                                className="btn-astra btn-danger-astra",
                                n_clicks=0,
                                style={"marginRight": "8px"},
                            ),
                            html.Button(
                                "✎ End & Write Report",
                                id="end-and-report-button",
                                className="btn-astra btn-primary-astra",
                                n_clicks=0,
                            ),
                        ],
                        style={"display": "flex"},
                    ),
                ],
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "marginBottom": "16px",
                },
            ),
            # Three-column grid: logs | alerts | triage panel
            html.Div(
                [
                    _log_stream_card(),
                    _alerts_card(),
                    _triage_panel(),
                ],
                className="live-grid live-grid-with-panel",
                style={
                    "display": "grid",
                    "gridTemplateColumns": "minmax(0, 1.4fr) minmax(0, 1fr) minmax(280px, 0.9fr)",
                    "gap": "16px",
                },
            ),
            html.Div(style={"height": "20px"}),
            _score_panel(),
        ],
    )


def _triage_panel() -> html.Div:
    """Right-side detail/triage panel. Hidden until an alert is clicked."""
    return html.Div(
        [
            html.Div(
                [
                    html.H3("Alert Detail", className="astra-card-title"),
                    html.Span(id="triage-panel-meta", className="astra-card-meta"),
                ],
                className="astra-card-header",
            ),
            html.Div(
                id="triage-panel-body",
                children=html.Div(
                    [
                        html.Div("◇", className="empty-state-icon"),
                        "Click an alert to investigate",
                    ],
                    className="empty-state",
                    style={"padding": "32px 16px"},
                ),
                style={
                    "padding": "12px 14px",
                    "minHeight": "300px",
                    "fontSize": "13px",
                },
            ),
        ],
        className="astra-card",
        id="triage-panel",
    )


def _render_triage_body(alert: dict) -> html.Div:
    """Render the body of the triage panel for the selected alert."""
    severity = (alert.get("severity") or "medium").lower()
    technique = alert.get("technique_id", "")
    description = alert.get("description") or alert.get("message") or "No description provided."
    rule_name = alert.get("rule_name") or alert.get("rule_id", "—")
    hostname = alert.get("hostname", "—")
    src_ip = alert.get("source_ip", "—")
    dst_ip = alert.get("destination_ip", "—")
    username = alert.get("username", "—")
    ts = alert.get("timestamp", "")
    triage = (alert.get("triage_status") or "new").lower()

    def _row(label: str, value: str) -> html.Div:
        return html.Div(
            [
                html.Span(label, style={
                    "color": "var(--text-secondary)",
                    "fontSize": "11px",
                    "textTransform": "uppercase",
                    "letterSpacing": "0.04em",
                    "minWidth": "80px",
                    "display": "inline-block",
                }),
                html.Span(str(value), style={
                    "fontFamily": "var(--font-mono)",
                    "fontSize": "12px",
                    "color": "var(--text-primary)",
                }),
            ],
            style={"marginBottom": "6px"},
        )

    triage_buttons = html.Div(
        [
            html.Button(
                "✓ True Positive",
                id="triage-tp-button",
                className="btn-astra btn-primary-astra",
                n_clicks=0,
                style={"flex": "1", "fontSize": "12px"},
            ),
            html.Button(
                "✗ False Positive",
                id="triage-fp-button",
                className="btn-astra btn-secondary-astra",
                n_clicks=0,
                style={"flex": "1", "fontSize": "12px"},
            ),
            html.Button(
                "↑ Escalate",
                id="triage-escalate-button",
                className="btn-astra btn-danger-astra",
                n_clicks=0,
                style={"flex": "1", "fontSize": "12px"},
            ),
        ],
        style={"display": "flex", "gap": "6px", "marginTop": "12px"},
    )

    notes_field = dcc.Textarea(
        id="triage-notes-input",
        value=alert.get("analyst_notes") or "",
        placeholder="Analyst notes (optional)…",
        style={
            "width": "100%",
            "minHeight": "80px",
            "marginTop": "12px",
            "fontFamily": "var(--font-mono)",
            "fontSize": "12px",
            "padding": "8px",
            "background": "var(--bg-input, #0a0a0a)",
            "color": "var(--text-primary)",
            "border": "1px solid var(--border-subtle, #2a2a2a)",
            "borderRadius": "4px",
        },
    )

    feedback = html.Div(
        id="triage-feedback-text",
        style={
            "marginTop": "8px",
            "fontSize": "11px",
            "color": "var(--status-good)",
            "minHeight": "16px",
        },
    )

    return html.Div(
        [
            # Title block
            html.Div(
                [
                    html.Span(severity.upper(), className=f"alert-severity-badge {severity}"),
                    html.Span(
                        triage.replace("_", " ").upper(),
                        style={
                            "marginLeft": "8px",
                            "fontSize": "10px",
                            "padding": "2px 8px",
                            "border": "1px solid var(--border-subtle, #2a2a2a)",
                            "borderRadius": "3px",
                            "color": "var(--text-secondary)",
                        },
                    ) if triage and triage != "new" else None,
                ],
                style={"marginBottom": "8px"},
            ),
            html.H4(
                alert.get("title", "Untitled alert"),
                style={"margin": "0 0 8px 0", "fontSize": "14px"},
            ),
            html.Div(
                description,
                style={
                    "fontSize": "12px",
                    "color": "var(--text-secondary)",
                    "marginBottom": "12px",
                    "lineHeight": "1.5",
                },
            ),
            # Metadata block
            html.Hr(style={"border": "0", "borderTop": "1px solid var(--border-subtle, #2a2a2a)"}),
            html.Div(
                [
                    _row("Rule",      rule_name),
                    _row("Technique", technique or "—"),
                    _row("Host",      hostname),
                    _row("User",      username),
                    _row("Source",    src_ip),
                    _row("Dest",      dst_ip),
                    _row("Time",      ts),
                ],
                style={"marginTop": "10px"},
            ),
            html.Hr(style={"border": "0", "borderTop": "1px solid var(--border-subtle, #2a2a2a)"}),
            # Triage controls
            html.Div("Triage decision", style={
                "fontSize": "11px",
                "textTransform": "uppercase",
                "color": "var(--text-secondary)",
                "letterSpacing": "0.04em",
                "marginTop": "12px",
            }),
            triage_buttons,
            notes_field,
            feedback,
        ],
    )

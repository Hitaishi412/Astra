"""
dashboard/callbacks/progress.py
────────────────────────────────
Callbacks for the Progress page.

Flow:
  1. On page load → progress data is fetched for the AUTHENTICATED user
     (the server resolves identity from the Firebase token; there is no
     user_id in the URL anymore — see api/routers/progress.py).
  2. Data stored in dcc.Store → renders summary stats + 4 charts.

SECURITY NOTE: the old /progress/users user-directory endpoint and the
/progress/{user_id}/... routes were removed (IDOR + user enumeration).
The picker is kept as a single static "Me" entry only so the existing
layout component stays valid; it no longer selects between users.

Auth: API calls carry the Firebase token via _auth.auth_headers +
State("auth-token","data"). Render callbacks make no API calls.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from dash import Input, Output, State, no_update

from dashboard.callbacks._auth import auth_headers
from dashboard.components.charts import (
    activity_calendar_chart,
    empty_chart,
    score_trend_chart,
    skills_radar_chart,
    tactic_heatmap_chart,
)


logger = logging.getLogger("astra.dashboard.progress")


def _fetch(url: str, timeout: float = 4.0, headers: dict | None = None) -> Any:
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(url, headers=headers or {})
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.debug(f"Progress fetch failed [{url}]: {e}")
        return None


def register(app):
    """Register all progress page callbacks."""

    # ── Picker is now a no-op single entry ───────────────────────────────
    # The user-directory endpoint was removed for security. Progress is
    # always the authenticated user. We keep one static option so the
    # layout's picker component stays valid and fetch_progress has a
    # trigger value.
    @app.callback(
        Output("progress-user-picker", "options"),
        Output("progress-user-picker", "value"),
        Input("url", "pathname"),
    )
    def populate_user_picker(pathname):
        if not pathname or not pathname.startswith("/progress"):
            return no_update, no_update
        return [{"label": "Me", "value": "me"}], "me"

    # ── Fetch all progress data for the authenticated user ───────────────
    @app.callback(
        Output("progress-data-store", "data"),
        Input("progress-user-picker", "value"),
        Input("progress-tick", "n_intervals"),
        State("api-base", "data"),
        State("auth-token", "data"),
    )
    def fetch_progress(_picker, _n, api_base, token):
        # Identity comes from the token server-side, not from the picker.
        if not token:
            return {}
        h = auth_headers(token)
        return {
            "summary":  _fetch(f"{api_base}/progress/summary",  headers=h) or {},
            "trends":   _fetch(f"{api_base}/progress/trends",   headers=h) or [],
            "skills":   _fetch(f"{api_base}/progress/skills",   headers=h) or {},
            "tactics":  _fetch(f"{api_base}/progress/tactics",  headers=h) or {},
            "activity": _fetch(f"{api_base}/progress/activity", headers=h) or [],
        }

    # ── Render summary stat blocks ───────────────────────────────────────
    @app.callback(
        Output("progress-stat-sessions", "children"),
        Output("progress-stat-avg",      "children"),
        Output("progress-stat-best",     "children"),
        Output("progress-stat-coverage", "children"),
        Input("progress-data-store", "data"),
    )
    def render_summary(data):
        if not data or not data.get("summary"):
            return "—", "—", "—", "—"
        s = data["summary"]
        return (
            str(s.get("total_sessions", 0)),
            f"{s.get('avg_score', 0):.0f}",
            f"{s.get('best_score', 0):.0f}",
            f"{s.get('avg_coverage', 0):.0f}%",
        )

    # ── Render score trend chart ─────────────────────────────────────────
    @app.callback(
        Output("progress-chart-trend", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_trend(data):
        if not data:
            return empty_chart("No data yet")
        trends = data.get("trends") or []
        rows = [
            {"date": t.get("date", ""), "score": t.get("score", 0), "mode": t.get("mode", "soc")}
            for t in trends
        ]
        return score_trend_chart(rows)

    # ── Render skills radar ─────────────────────────────────────────────
    @app.callback(
        Output("progress-chart-radar", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_radar(data):
        if not data:
            return empty_chart("No data yet")
        skills = data.get("skills") or {}
        return skills_radar_chart(skills)

    # ── Render tactic heatmap ─────────────────────────────────────────
    @app.callback(
        Output("progress-chart-heatmap", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_heatmap(data):
        if not data:
            return empty_chart("No data yet")
        tactics = data.get("tactics") or {}
        return tactic_heatmap_chart(tactics)

    # ── Render activity calendar ─────────────────────────────────────────
    @app.callback(
        Output("progress-chart-activity", "figure"),
        Input("progress-data-store", "data"),
    )
    def render_activity(data):
        if not data:
            return empty_chart("No data yet")
        activity = data.get("activity") or []
        return activity_calendar_chart(activity)

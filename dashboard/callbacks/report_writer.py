"""
dashboard/callbacks/report_writer.py
─────────────────────────────────────
Callbacks for the report writer page.

Flow:
  1. On page load → fetch template + facts → render section cards + facts panel
  2. As student types → update local store + word counters
  3. Periodic tick → autosave draft to backend
  4. Submit button → POST submit, show scorecard
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from dash import ALL, MATCH, Input, Output, State, ctx, html, no_update

from dashboard.callbacks._auth import auth_headers
logger = logging.getLogger("astra.dashboard.report_writer")


def _safe_get(url: str, timeout: float = 4.0, headers: dict | None = None) -> Any:
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(url, headers=headers or {})
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.debug(f"GET {url} failed: {e}")
        return None


def _safe_post(url: str, json: dict, timeout: float = 8.0, headers: dict | None = None) -> Any:
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(url, json=json, headers=headers or {})
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.debug(f"POST {url} failed: {e}")
        return None


def _word_count(text: str) -> int:
    return len(re.findall(r"\b\w+\b", text or ""))


def register(app):
    """Register report writer callbacks."""

    # ── On page load: fetch template + facts + existing draft ───────────
    @app.callback(
        Output("rw-template", "data"),
        Output("rw-facts", "data"),
        Output("rw-content", "data"),
        Output("rw-submitted", "data"),
        Input("rw-session-id", "data"),
        Input("rw-report-type", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
    )
    def load_initial_data(session_id, report_type, api_base, token):
        if not session_id or not report_type:
            return no_update, no_update, no_update, no_update

        # Fetch template
        # Map report_type to mode (incident -> any mode that uses it)
        # Just use mode=soc for incident, mode=pentester for pentest
        mode = "soc" if report_type == "incident" else "pentester"
        templates = _safe_get(f"{api_base}/reports/templates/{mode}", headers=auth_headers(token)) or []
        template = next((t for t in templates if t["id"] == report_type), None)
        if template is None:
            template = templates[0] if templates else {"id": report_type, "sections": []}

        # Fetch facts
        facts = _safe_get(f"{api_base}/reports/{session_id}/facts", headers=auth_headers(token)) or {}

        # Try to load existing draft
        existing = _safe_get(f"{api_base}/reports/{session_id}/{report_type}", headers=auth_headers(token))
        content = (existing or {}).get("content", {})
        submitted = (existing or {}).get("submitted", False)

        return template, facts, content, submitted

    # ── Render section cards once template is loaded ─────────────────────
    @app.callback(
        Output("rw-sections-container", "children"),
        Input("rw-template", "data"),
        State("rw-content", "data"),
    )
    def render_section_cards(template, existing_content):
        if not template or "sections" not in template:
            return html.Div("Loading template…", className="empty-state")

        from dashboard.layouts.report_writer import _section_card

        sections = []
        for section in template["sections"]:
            card = _section_card(
                section_id=section["id"],
                title=section["title"],
                prompt=section["prompt"],
                placeholder=section.get("placeholder", ""),
                required=section.get("required", True),
                min_words=section.get("min_words", 50),
            )
            # If content exists for this section, prefill — Dash needs the
            # textarea in the layout first, but we pre-set the value.
            sections.append(card)

        return sections

    # ── Render facts panel ───────────────────────────────────────────────
    @app.callback(
        Output("rw-facts-content", "children"),
        Input("rw-facts", "data"),
    )
    def render_facts(facts):
        if not facts:
            return html.Div("No facts available yet.", className="empty-state")

        def fact_block(label: str, items: list[str], color_class: str = "") -> html.Div:
            if not items:
                return None
            return html.Div(
                [
                    html.Div(label, className=f"rw-fact-label {color_class}"),
                    html.Div(
                        [html.Span(item, className=f"rw-fact-pill {color_class}") for item in items],
                        className="rw-fact-pills",
                    ),
                ],
                className="rw-fact-group",
            )

        blocks = [
            fact_block("MITRE Techniques Used", facts.get("techniques_used", []), "mitre"),
            fact_block("Detected", facts.get("techniques_detected", []), "detected"),
            fact_block("Missed", facts.get("techniques_missed", []), "missed"),
            fact_block("Hostnames", facts.get("hostnames", [])),
            fact_block("IP Addresses", facts.get("ip_addresses", [])),
            fact_block("Usernames", facts.get("usernames", [])),
            fact_block("Processes", facts.get("processes", [])),
        ]

        # Metrics summary
        metrics = html.Div(
            [
                html.Div(
                    [
                        html.Div(str(facts.get("total_attack_steps", 0)), className="rw-metric-num"),
                        html.Div("Attack Steps", className="rw-metric-label"),
                    ],
                    className="rw-metric-block",
                ),
                html.Div(
                    [
                        html.Div(str(facts.get("total_alerts", 0)), className="rw-metric-num"),
                        html.Div("Alerts Fired", className="rw-metric-label"),
                    ],
                    className="rw-metric-block",
                ),
                html.Div(
                    [
                        html.Div(f"{facts.get('coverage_pct', 0):.0f}%", className="rw-metric-num"),
                        html.Div("Coverage", className="rw-metric-label"),
                    ],
                    className="rw-metric-block",
                ),
            ],
            className="rw-metrics-row",
        )

        return [metrics] + [b for b in blocks if b is not None]

    # ── Word counter (per-section) ───────────────────────────────────────
    @app.callback(
        Output({"type": "rw-wordcount", "section": MATCH}, "children"),
        Input({"type": "rw-section", "section": MATCH}, "value"),
    )
    def update_wordcount(text):
        return f"{_word_count(text or '')} words"

    # ── Prefill textareas when content store is populated ────────────────
    @app.callback(
        Output({"type": "rw-section", "section": ALL}, "value"),
        Input("rw-content", "data"),
        State({"type": "rw-section", "section": ALL}, "id"),
        prevent_initial_call=True,
    )
    def prefill_textareas(content, section_ids):
        if not content:
            return [no_update] * len(section_ids)
        return [content.get(sid["section"], "") for sid in section_ids]

    # ── Autosave on tick ─────────────────────────────────────────────────
    @app.callback(
        Output("rw-status", "children"),
        Output("rw-status", "className"),
        Input("rw-autosave-tick", "n_intervals"),
        State({"type": "rw-section", "section": ALL}, "value"),
        State({"type": "rw-section", "section": ALL}, "id"),
        State("rw-session-id", "data"),
        State("rw-report-type", "data"),
        State("rw-submitted", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
    )
    def autosave(n, values, ids, session_id, report_type, submitted, api_base, token):
        if not session_id or not values or submitted:
            return no_update, no_update
        # Only save if there's any content
        content = {sid["section"]: (val or "") for sid, val in zip(ids, values)}
        if not any(v.strip() for v in content.values()):
            return "Draft (empty)", "rw-status-value muted"

        result = _safe_post(
            f"{api_base}/reports/{session_id}/draft",
            json={"report_type": report_type, "content": content},
            headers=auth_headers(token),
        )
        if result:
            return "Saved", "rw-status-value saved"
        return "Save failed", "rw-status-value error"

    # ── Save Draft button (manual) ───────────────────────────────────────
    @app.callback(
        Output("rw-status", "children", allow_duplicate=True),
        Output("rw-status", "className", allow_duplicate=True),
        Input("rw-save-button", "n_clicks"),
        State({"type": "rw-section", "section": ALL}, "value"),
        State({"type": "rw-section", "section": ALL}, "id"),
        State("rw-session-id", "data"),
        State("rw-report-type", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
        prevent_initial_call=True,
    )
    def save_draft(n_clicks, values, ids, session_id, report_type, api_base, token):
        if not n_clicks or not session_id:
            return no_update, no_update
        content = {sid["section"]: (val or "") for sid, val in zip(ids, values)}
        result = _safe_post(
            f"{api_base}/reports/{session_id}/draft",
            json={"report_type": report_type, "content": content},
            headers=auth_headers(token),
        )
        if result:
            return "Draft saved", "rw-status-value saved"
        return "Save failed", "rw-status-value error"

    # ── Submit button ────────────────────────────────────────────────────
    @app.callback(
        Output("rw-scorecard", "children"),
        Output("rw-scorecard", "style"),
        Output("rw-status", "children", allow_duplicate=True),
        Output("rw-status", "className", allow_duplicate=True),
        Output("rw-submitted", "data", allow_duplicate=True),
        Output("rw-autosave-tick", "disabled"),
        Input("rw-submit-button", "n_clicks"),
        State({"type": "rw-section", "section": ALL}, "value"),
        State({"type": "rw-section", "section": ALL}, "id"),
        State("rw-session-id", "data"),
        State("rw-report-type", "data"),
        State("api-base", "data"),
        State("auth-token", "data"),
        prevent_initial_call=True,
    )
    def submit_report(n_clicks, values, ids, session_id, report_type, api_base, token):
        if not n_clicks or not session_id:
            return no_update, no_update, no_update, no_update, no_update, no_update
        content = {sid["section"]: (val or "") for sid, val in zip(ids, values)}
        result = _safe_post(
            f"{api_base}/reports/{session_id}/submit",
            json={"report_type": report_type, "content": content},
            headers=auth_headers(token),
        )
        if not result:
            return no_update, no_update, "Submit failed", "rw-status-value error", no_update, no_update

        scorecard = _build_scorecard(result.get("score", {}))
        return (
            scorecard,
            {"display": "block", "marginTop": "32px"},
            "Submitted",
            "rw-status-value submitted",
            True,
            True,  # disable autosave
        )


def _build_scorecard(score: dict) -> html.Div:
    """Render the final scorecard after submission."""
    overall = score.get("overall_score", 0)
    grade = score.get("grade", "—")
    summary = score.get("summary_feedback", [])
    dimensions = score.get("dimensions", {})

    # Overall hero
    hero = html.Div(
        [
            html.Div(
                [
                    html.Div(f"{overall:.0f}", className="score-number"),
                    html.Div(grade.upper().replace("_", " "), className=f"score-grade {grade.lower()}"),
                ],
                className="score-hero",
            ),
            html.Div(
                [html.P(s, className="rw-summary-line") for s in summary],
                className="rw-summary",
            ),
        ],
    )

    # Dimensions breakdown
    dim_blocks = []
    for name, dim in dimensions.items():
        score_val = dim.get("score", 0)
        weight = dim.get("weight", 0)
        feedback_items = dim.get("feedback", [])

        # Color the bar based on score
        if score_val >= 80:
            bar_class = "rw-dim-bar good"
        elif score_val >= 60:
            bar_class = "rw-dim-bar ok"
        elif score_val >= 40:
            bar_class = "rw-dim-bar warn"
        else:
            bar_class = "rw-dim-bar bad"

        dim_blocks.append(html.Div(
            [
                html.Div(
                    [
                        html.Span(name.upper(), className="rw-dim-name"),
                        html.Span(
                            f"{score_val:.0f} / 100",
                            className="rw-dim-score",
                        ),
                        html.Span(
                            f"weight {int(weight * 100)}%",
                            className="rw-dim-weight",
                        ),
                    ],
                    className="rw-dim-header",
                ),
                # Progress bar
                html.Div(
                    html.Div(className=bar_class, style={"width": f"{score_val}%"}),
                    className="rw-dim-bar-track",
                ),
                # Feedback
                html.Ul(
                    [html.Li(item, className="rw-dim-feedback-item") for item in feedback_items],
                    className="rw-dim-feedback",
                ) if feedback_items else None,
            ],
            className="rw-dim-block",
        ))

    return html.Div(
        [
            html.Div(
                [
                    html.H3("Report Scorecard", className="astra-card-title"),
                    html.Span("FINAL EVALUATION", className="astra-card-meta"),
                ],
                className="astra-card-header",
            ),
            hero,
            html.Div("Dimension Breakdown", className="section-heading"),
            html.Div(dim_blocks, className="rw-dimensions"),
        ],
        className="astra-card rw-scorecard",
    )

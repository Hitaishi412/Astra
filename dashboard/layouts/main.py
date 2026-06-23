"""
dashboard/layouts/main.py
──────────────────────────
Persistent navbar that wraps every page.
"""
from __future__ import annotations
from dash import dcc, html

_NAV_ITEMS = [
    ("/",            "Modes"),
    ("/progress",    "Progress"),
    ("/history",     "History"),
    ("/leaderboard", "Leaderboard"),
    ("/matrix",      "ATT&CK"),
]

def navbar() -> html.Nav:
    """Top navigation bar (persistent across all pages)."""
    return html.Nav(
        [
            html.Div("ASTRA", className="astra-nav-brand"),
            html.Div(
                [
                    dcc.Link(label, href=path, className="astra-nav-link")
                    for path, label in _NAV_ITEMS
                ],
                className="astra-nav-links",
            ),
            html.Div(
                [
                    html.Span(className="status-dot"),
                    html.Span("LIVE", id="navbar-status-text"),
                ],
                className="astra-nav-status",
            ),
            html.Button(
                "Sign out",
                id="logout-btn",
                className="astra-nav-logout",
            ),
        ],
        className="astra-nav",
    )

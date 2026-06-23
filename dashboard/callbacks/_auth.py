"""
dashboard/callbacks/_auth.py
─────────────────────────────
Single source of truth for turning the client-side Firebase ID token into
the HTTP header the API expects.

Every dashboard callback that calls the backend should build its request
headers through `auth_headers(token)`, where `token` comes from
State("auth-token", "data"). This is the helper Phase 2 reuses verbatim in
progress.py / report_writer.py / streaming.py / pentester.py — do not
reimplement the header logic per file.

Server side: api/firebase_auth.py reads `Authorization: Bearer <token>`.
When FIREBASE_ENABLED=false it ignores the token and falls back to the demo
user, so sending the header (or not) is harmless in local dev — which makes
it safe to wire everywhere before flipping the flag.
"""

from __future__ import annotations


def auth_headers(token: str | None) -> dict[str, str]:
    """Return request headers for an API call.

    Includes `Authorization: Bearer <token>` when a non-empty token is
    present; returns an empty dict otherwise (so unauthenticated/local-dev
    calls still work against the demo-user fallback).
    """
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

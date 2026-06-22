"""
security_headers.py   (put this at the repo root, next to run.py)
-----------------------------------------------------------------
Adds standard security response headers to both the FastAPI API and the Dash
dashboard. Wire it in once per app (see below).

WIRE-IN:

    # API -- after you create the FastAPI app (api/main.py, api/app.py, or run.py):
    from security_headers import apply_to_fastapi
    apply_to_fastapi(app)

    # Dashboard -- after you create the Dash app (dashboard/app.py or run.py):
    from security_headers import apply_to_flask
    apply_to_flask(app.server)        # Dash exposes the underlying Flask app as .server

WHAT IT SETS:
  - COMMON_HEADERS: safe to ENFORCE everywhere; they don't change app behaviour.
  - API: serves JSON only, so it gets a strict ENFORCED CSP (default-src 'none').
  - Dashboard: Dash + Firebase use inline scripts / eval, so a strict CSP needs
    nonces/hashes. Until you wire those, the dashboard CSP ships REPORT-ONLY --
    it logs violations to the browser console but does NOT block, so it cannot
    break your live app. Open DevTools -> Console, sign in, click around, then
    widen/trim DASHBOARD_CSP to match what's actually loaded. Once it's quiet,
    flip the dashboard call to enforce it:
        apply_to_flask(app.server, csp_report_only=False)
"""

from __future__ import annotations

# Safe to enforce everywhere -- these do not alter how the app works.
COMMON_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",                       # clickjacking (legacy)
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

# API returns JSON only -> lock everything down.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

# Dashboard: Dash + Firebase need inline scripts/eval and a few Google origins.
# Shipped REPORT-ONLY first (see module docstring). Tighten before enforcing.
DASHBOARD_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
        "https://www.gstatic.com https://apis.google.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self' "
        "https://*.googleapis.com https://*.firebaseio.com "
        "https://identitytoolkit.googleapis.com https://securetoken.googleapis.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
])


def _csp_header_name(report_only: bool) -> str:
    return "Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"


def apply_to_fastapi(app, *, csp: str = API_CSP, csp_report_only: bool = False) -> None:
    """Register a middleware on a FastAPI/Starlette app that sets the headers."""

    @app.middleware("http")
    async def _security_headers(request, call_next):
        response = await call_next(request)
        for key, value in COMMON_HEADERS.items():
            response.headers.setdefault(key, value)
        if csp:
            response.headers.setdefault(_csp_header_name(csp_report_only), csp)
        return response


def apply_to_flask(server, *, csp: str = DASHBOARD_CSP, csp_report_only: bool = True) -> None:
    """Register an after_request hook on a Flask server (Dash's app.server)."""

    @server.after_request
    def _security_headers(response):
        for key, value in COMMON_HEADERS.items():
            response.headers.setdefault(key, value)
        if csp:
            response.headers.setdefault(_csp_header_name(csp_report_only), csp)
        return response

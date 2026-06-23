"""
api/rate_limit.py
──────────────────
Redis-backed rate limiting via SlowAPI, applied globally as middleware.

Why Redis (not in-memory):
  The API runs on Render's free tier, which spins down on inactivity and can
  run more than one instance. An in-memory limiter would reset on every
  spin-down and wouldn't be shared across instances. Backing it with the same
  Upstash Redis the streaming layer already uses makes limits durable.

Why middleware (not per-route decorators):
  SlowAPIMiddleware enforces `default_limits` on EVERY route automatically,
  so we don't have to add `request: Request` to every handler signature or
  decorate each endpoint. One global cap, wired in one place.

Key strategy:
  Prefer the Firebase uid when the request carries a bearer token, so
  authenticated users are limited per-account (important behind a shared campus
  NAT). Fall back to client IP for anonymous traffic. The uid is read from the
  UNVERIFIED token payload purely as a bucketing key — real verification still
  happens in get_current_user, so forging a uid only changes which throttle
  bucket you land in, never whether you're allowed through.

Resilience:
  Redis is pinged synchronously at startup. If it's unreachable, we log a
  CRITICAL and fall back to an in-memory limiter so the limiter can never take
  the whole API down — it degrades instead of failing closed on the DB hop.

Tuning:
  RATE_LIMIT_DEFAULT env var overrides the default limit (e.g. "60/minute")
  without a code change.

Wire-in (api/app.py, inside create_app after the app exists):
    from api.rate_limit import init_rate_limiter
    init_rate_limiter(app)
"""

from __future__ import annotations

import logging
import os

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.requests import Request
from starlette.responses import JSONResponse

from config.settings import get_settings

logger = logging.getLogger("astra.rate_limit")

# Resolved once at import; also used in the attach log line.
DEFAULT_LIMIT = os.getenv("RATE_LIMIT_DEFAULT", "120/minute")


def _uid_from_unverified_jwt(token: str) -> str | None:
    """Best-effort extract user_id/sub from a JWT payload WITHOUT verifying.
    Returns None on anything malformed (caller falls back to IP)."""
    import base64
    import binascii
    import json

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)  # JWT is base64url, no padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        uid = claims.get("user_id") or claims.get("sub") or claims.get("uid")
        return str(uid) if uid else None
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return None


def _client_key(request: Request) -> str:
    """Bucket key: Firebase uid if a bearer token is present, else client IP."""
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        uid = _uid_from_unverified_jwt(auth[7:].strip())
        if uid:
            return f"uid:{uid}"
    return f"ip:{get_remote_address(request)}"


def _build_limiter() -> Limiter:
    settings = get_settings()
    redis_url = getattr(settings, "redis_url", None)

    common = dict(
        key_func=_client_key,
        default_limits=[DEFAULT_LIMIT],
        headers_enabled=True,  # emit X-RateLimit-* response headers
    )

    if redis_url and not redis_url.startswith("redis://localhost"):
        try:
            # Synchronous reachability check (sync fn, called at import time).
            import redis
            redis.Redis.from_url(redis_url, socket_connect_timeout=2).ping()
            logger.info(f"[rate_limit] Redis reachable at {redis_url.split('@')[-1]}")
            return Limiter(storage_uri=redis_url, **common)
        except Exception as e:
            # Degrade, don't die: a flaky limiter store must not 503 the API.
            logger.critical(
                f"[rate_limit] Redis unreachable ({e}); falling back to in-memory limiter."
            )
    else:
        logger.warning("[rate_limit] no production Redis URL; in-memory limiter (dev only)")

    return Limiter(**common)


# Singleton — import this in routers for per-route @limiter.limit overrides.
limiter = _build_limiter()


async def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"},
    )


def init_rate_limiter(app) -> None:
    """Attach the limiter, the 429 handler, and the global middleware.
    Call inside create_app() after the app object exists."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    logger.info(f"[rate_limit] global limiter attached (default {DEFAULT_LIMIT} per uid/IP)")


# ── Optional per-route tighter limits (handler must take `request: Request`) ──
#   from api.rate_limit import limiter
#   @router.post("/sessions")
#   @limiter.limit("10/minute")
#   async def create_session(request: Request, ...): ...
"""
api/firebase_auth.py
─────────────────────
Firebase Auth integration for FastAPI.

How it works:
  1. The Dash frontend (or any client) signs the user in via Firebase Auth.
  2. Firebase returns an ID token (a JWT signed by Firebase's private key).
  3. Every API call includes that token:
       Authorization: Bearer <firebase_id_token>
  4. This module verifies the token against Firebase's public keys.
  5. On success, it upserts the user into our `users` table and returns
     the User ORM object as a FastAPI dependency.

Setup:
  Set these environment variables in production (Render) or .env locally:
    FIREBASE_PROJECT_ID=your-project-id   (e.g. "astra-cyber-abc12")
    FIREBASE_SERVICE_ACCOUNT_B64=<base64 of the service-account JSON>

  The firebase-admin SDK automatically fetches Firebase's public keys
  from Google — no private key needed for server-side token verification.

Auth modes (IMPORTANT — fail closed):
  - Production: FIREBASE_PROJECT_ID is set and FIREBASE_ENABLED != "false".
    If Firebase fails to initialise (bad/missing credentials), the request
    is REFUSED (503) — we never silently demote to the shared demo user.
  - Local dev: leave FIREBASE_PROJECT_ID unset, or set FIREBASE_ENABLED=false,
    to intentionally run without Firebase (all requests become the demo user).
    This fallback only happens when Firebase is *deliberately* disabled.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.deps import get_db
from db.models import User

from api.email_allowlist import assert_allowed_email

logger = logging.getLogger("astra.firebase_auth")

# ---------------------------------------------------------------------------
# Firebase Admin SDK initialisation (lazy, once)
# ---------------------------------------------------------------------------
_firebase_initialised = False

def _get_firebase_credentials():
    """Resolve a Firebase credential.

    Prefers FIREBASE_SERVICE_ACCOUNT_B64 env var (production — Render),
    falls back to secrets/firebase-admin.json (local dev). Raises if
    neither is available so misconfiguration fails loudly instead of
    silently demoting to dev fallback."""
    import base64
    import json
    import os as _os
    from firebase_admin import credentials as _creds

    b64 = _os.environ.get("FIREBASE_SERVICE_ACCOUNT_B64")
    if b64:
        cert_dict = json.loads(base64.b64decode(b64))
        return _creds.Certificate(cert_dict)
    if _os.path.exists("secrets/firebase-admin.json"):
        return _creds.Certificate("secrets/firebase-admin.json")
    raise RuntimeError(
        "Firebase credentials not found. Set FIREBASE_SERVICE_ACCOUNT_B64 "
        "(production) or place secrets/firebase-admin.json (local dev)."
    )


def _init_firebase() -> bool:
    """
    Initialise the Firebase Admin SDK.

    Returns True if Firebase is active. Returns False ONLY when Firebase is
    intentionally disabled for local dev (FIREBASE_PROJECT_ID unset, or
    FIREBASE_ENABLED=false). RAISES if Firebase is meant to be on but fails to
    initialise — so production fails CLOSED instead of silently demoting every
    request to the shared demo user.
    """
    global _firebase_initialised

    if _firebase_initialised:
        return True

    project_id = os.environ.get("FIREBASE_PROJECT_ID")
    enabled = os.environ.get("FIREBASE_ENABLED", "true").lower() != "false"

    # Intentional dev mode -> allow the demo fallback in get_current_user.
    if not project_id or not enabled:
        logger.warning(
            "[firebase] FIREBASE_PROJECT_ID not set or FIREBASE_ENABLED=false — "
            "running in dev fallback mode (all requests treated as demo user)"
        )
        return False

    # Production: Firebase MUST initialise. If it can't, let the error
    # propagate so get_current_user fails CLOSED — we never silently demote
    # to the shared demo user (that would be a full auth bypass).
    import firebase_admin

    if not firebase_admin._apps:
        firebase_admin.initialize_app(
            credential=_get_firebase_credentials(),
            options={"projectId": project_id},
        )
    _firebase_initialised = True
    logger.info(f"[firebase] Initialised for project {project_id}")
    return True


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


async def _verify_firebase_token(token: str) -> dict:
    """
    Verify a Firebase ID token and return the decoded claims.
    Raises HTTPException 401 on failure.
    """
    try:
        from firebase_admin import auth as firebase_auth
        decoded = firebase_auth.verify_id_token(token, check_revoked=True)
        return decoded
    except Exception as e:
        logger.warning(f"[firebase] Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Firebase token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# User upsert — maps Firebase UID → our users table
# ---------------------------------------------------------------------------

async def _get_or_create_user_from_firebase(
    db: AsyncSession,
    firebase_uid: str,
    email: Optional[str],
    display_name: Optional[str],
) -> User:
    """
    Look up a user by firebase_uid. If not found, create them.
    Also syncs email and display_name on each login.
    """
    import uuid

    # Try by firebase_uid
    result = await db.execute(
        select(User).where(User.firebase_uid == firebase_uid)
    )
    user = result.scalar_one_or_none()

    if user is None:
        # New user — create them
        username = _derive_username(email, firebase_uid)
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            firebase_uid=firebase_uid,
            email=email,
            display_name=display_name or username,
        )
        db.add(user)
        await db.flush()
        logger.info(f"[firebase] Created new user {user.id} for uid {firebase_uid}")
    else:
        # Returning user — sync latest email/display_name from Firebase
        if email and user.email != email:
            user.email = email
        if display_name and user.display_name != display_name:
            user.display_name = display_name

    return user


def _derive_username(email: Optional[str], firebase_uid: str) -> str:
    """Derive a username from email or fall back to a short UID prefix."""
    if email:
        # Use everything before the @ symbol, strip non-alphanumeric except _
        local = email.split("@")[0]
        clean = "".join(c for c in local if c.isalnum() or c == "_")
        if clean:
            return clean[:64]
    # Fallback: first 12 chars of UID (always unique)
    return f"user_{firebase_uid[:12]}"


# ---------------------------------------------------------------------------
# FastAPI dependency — use in any endpoint that needs the current user
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency that returns the authenticated User.

    Usage in a router:
        @router.post("/sessions")
        async def create_session(
            body: SessionCreate,
            user: User = Depends(get_current_user),
            db: AsyncSession = Depends(get_db),
        ):
            ...

    In intentional dev mode (no FIREBASE_PROJECT_ID, or FIREBASE_ENABLED=false)
    returns the demo user so local development works without Firebase config.
    In production, a Firebase init failure returns 503 (fail closed), never the
    demo user.
    """
    try:
        firebase_active = _init_firebase()
    except Exception as e:
        # Firebase is configured but failed to initialise -> fail CLOSED.
        # Refuse the request instead of treating everyone as the demo user.
        logger.exception(f"[firebase] init error — refusing request: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable.",
        )

    # ── Development fallback (only when Firebase is intentionally disabled) ──
    if not firebase_active:
        result = await db.execute(
            select(User).where(User.username == "demo")
        )
        demo = result.scalar_one_or_none()
        if demo is None:
            import uuid
            demo = User(
                id=str(uuid.uuid4()),
                username="demo",
                display_name="Demo User",
                firebase_uid=None,
                email=None,
            )
            db.add(demo)
            await db.flush()
        return demo

    # ── Production: require Bearer token ───────────────────────────────
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    decoded = await _verify_firebase_token(credentials.credentials)

    uid   = decoded.get("uid")
    email = decoded.get("email")
    name  = decoded.get("name") or decoded.get("display_name")

    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing uid claim.",
        )

    # Only allow accounts from approved email providers (see email_allowlist.py)
    assert_allowed_email(email)

    user = await _get_or_create_user_from_firebase(db, uid, email, name)
    return user


# ---------------------------------------------------------------------------
# Optional current user (returns None if unauthenticated, for public routes)
# ---------------------------------------------------------------------------

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Like get_current_user but returns None instead of raising 401.
    Use for endpoints that work both authenticated and anonymous.
    """
    try:
        return await get_current_user(credentials=credentials, db=db)
    except HTTPException:
        return None
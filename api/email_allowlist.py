"""
api/email_allowlist.py
----------------------
Signup gate: restrict accounts to an allowlist of email providers.

Enforced server-side in get_current_user (api/firebase_auth.py), right after the
Firebase ID token is verified. Firebase itself still allows open self-signup, so
a disallowed account may be *created* in Firebase -- but the API refuses to serve
it (403), so it's inert (no usable session, ideally no DB row). To block creation
entirely you'd need a Firebase Auth blocking function (Blaze plan); this gate
needs no plan upgrade and is the "never trust the client" enforcement point.

Edit ALLOWED_EMAIL_DOMAINS to taste -- trim aliases you don't want, or add more.
"""

from __future__ import annotations

from fastapi import HTTPException, status

# Allowed providers -> their mail domains (including known aliases).
ALLOWED_EMAIL_DOMAINS: frozenset[str] = frozenset({
    # Gmail
    "gmail.com", "googlemail.com",
    # DuckDuckGo Email Protection
    "duck.com",
    # Proton  (proton.me current; protonmail.* legacy; pm.me short alias)
    "proton.me", "protonmail.com", "protonmail.ch", "pm.me",
    # Tuta / Tutanota
    "tutamail.com", "tuta.com", "tutanota.com", "tutanota.de", "keemail.me",
    # Apple iCloud Mail  (icloud.com current; me.com / mac.com legacy)
    "icloud.com", "me.com", "mac.com",
})


def email_domain(email: str | None) -> str:
    """Lower-cased domain part of an email, or '' if missing/malformed."""
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[-1].strip().lower()


def is_allowed_email(email: str | None) -> bool:
    """True if the email's provider domain is on the allowlist."""
    return email_domain(email) in ALLOWED_EMAIL_DOMAINS


def assert_allowed_email(email: str | None) -> None:
    """Raise 403 if the email's provider isn't allowed."""
    if not is_allowed_email(email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This email provider isn't supported. Sign up with Gmail, "
                "DuckDuckGo (@duck.com), Proton, Tuta, or iCloud / Apple Mail."
            ),
        )

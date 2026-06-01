"""
db/engine.py
─────────────
Async SQLAlchemy engine — Postgres via asyncpg.

The database URL is read from the DATABASE_URL environment variable,
which on Koyeb is injected from the dashboard's env-vars UI:

    DATABASE_URL=postgresql+asyncpg://postgres.<ref>:<password>@aws-1-<region>.pooler.supabase.com:5432/postgres

Falls back to the settings value (which you can set in .env locally
for development — see .env.example).

Key differences from the SQLite version:
  - Driver is asyncpg, not aiosqlite
  - connect_args removed (SQLite-only argument)
  - poolclass=NullPool: we connect through Supabase's Supavisor pooler,
    which already pools connections server-side. Letting SQLAlchemy keep
    its own pool on top of that caused asyncpg connections to be reused
    across different asyncio event loops (seed loop vs. uvicorn loop),
    raising "got Future attached to a different loop". NullPool opens a
    fresh connection per checkout and closes it on return, so every
    connection lives entirely within the loop that created it.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from config.settings import get_settings

# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_database_url() -> str:
    """
    Resolve the database URL.

    Priority:
    1. DATABASE_URL env var (set by Koyeb env-vars UI in production)
    2. settings.database_url (from .env or config.yaml locally)

    Supabase gives you a connection string starting with
    'postgresql://...' — we rewrite it to use the asyncpg driver.
    """
    raw = os.environ.get("DATABASE_URL") or get_settings().database_url

    # Supabase and most Postgres providers give a plain 'postgresql://' URL.
    # SQLAlchemy needs the async variant 'postgresql+asyncpg://'.
    if raw.startswith("postgresql://"):
        raw = raw.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif raw.startswith("postgres://"):
        # Some providers (Heroku legacy) use this alias
        raw = raw.replace("postgres://", "postgresql+asyncpg://", 1)

    return raw


def get_engine() -> AsyncEngine:
    """Return the global async engine, creating it if needed."""
    global _engine
    if _engine is None:
        db_url = _build_database_url()
        settings = get_settings()
        _engine = create_async_engine(
            db_url,
            echo=settings.db_echo,
            # We sit behind Supabase Supavisor (the session pooler on
            # :5432), which handles connection pooling server-side.
            # NullPool tells SQLAlchemy NOT to keep its own pool: each
            # checkout opens a new asyncpg connection and closes it on
            # return. This is the documented pattern for external poolers
            # and it eliminates the cross-event-loop error that occurs
            # when run.py seeds in one asyncio loop and then serves the
            # app in a second loop while reusing a cached pool.
            poolclass=NullPool,
            # Transaction-mode pooler (Supavisor :6543) can route each
            # transaction to a different backend, which breaks asyncpg's
            # prepared-statement cache. Disable asyncpg's cache and
            # SQLAlchemy's dialect cache. Harmless on the :5432 session
            # pooler too, so it's safe regardless of the URL port.
            connect_args={
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
            },
        )
    return _engine


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the global session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------
@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async session that auto-commits on success, rolls back on error."""
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# FastAPI dependency (for use in router endpoints)
# ---------------------------------------------------------------------------
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI-compatible dependency that yields a DB session."""
    async with get_session() as session:
        yield session


# ---------------------------------------------------------------------------
# Init — tables already created by Supabase migration; this is effectively
# a no-op for Postgres but kept for backward compatibility with run.py
# ---------------------------------------------------------------------------
async def init_db() -> None:
    """
    On Postgres (production), tables are managed by migrations applied via
    the Supabase MCP connector or Alembic. This function is kept for
    compatibility with run.py's startup sequence — calling create_all
    is safe (it's idempotent) but in practice nothing new gets created
    because the schema was applied by migration.

    On local SQLite (development fallback), this creates the tables.
    """
    from db.models import Base  # noqa: import here to avoid circular imports

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("[DB] Tables ready.")


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
async def close_db() -> None:
    """Dispose of the engine connection pool."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
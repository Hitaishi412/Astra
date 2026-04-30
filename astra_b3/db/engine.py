"""
Database engine — async SQLAlchemy setup with SQLite.
Usage:
    from db.engine import init_db, get_session

    # At startup
    await init_db()

    # In a request
    async with get_session() as session:
        result = await session.execute(...)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from config.settings import get_settings

# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the global async engine, creating it if needed."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.db_echo,
            connect_args={"check_same_thread": False},  # Required for SQLite
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
# Init — create all tables
# ---------------------------------------------------------------------------
async def init_db() -> None:
    """Create all tables defined in models.py. Safe to call multiple times."""
    from db.models import Base  # noqa: import here to avoid circular imports

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("[DB] Tables created successfully.")


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

"""
Health check endpoints — verify API and database are running.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "astra-api"}


@router.get("/ready")
async def readiness_check():
    """Check that the database is reachable."""
    try:
        from db.engine import get_engine
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        return {"status": "not_ready", "database": str(e)}


from sqlalchemy import text

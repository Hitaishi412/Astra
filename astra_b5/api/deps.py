"""
FastAPI dependencies — injectable via Depends().
"""

from sqlalchemy.ext.asyncio import AsyncSession
from db.engine import get_db_session

# Re-export for clean imports in routers
# Usage: async def endpoint(db: AsyncSession = Depends(get_db)):
get_db = get_db_session

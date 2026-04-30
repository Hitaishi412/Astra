"""
Reset database — drops all tables and recreates them.
WARNING: This deletes all data.

Run with: python scripts/reset_db.py
"""

import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.engine import get_engine, init_db
from db.models import Base


async def reset():
    print("[RESET] Dropping all tables...")
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    print("[RESET] All tables dropped.")

    print("[RESET] Recreating tables...")
    await init_db()
    print("[RESET] Done. Database is empty and ready.")


if __name__ == "__main__":
    confirm = input("This will DELETE ALL DATA. Type 'yes' to confirm: ")
    if confirm.strip().lower() == "yes":
        asyncio.run(reset())
    else:
        print("Aborted.")

"""
ASTRA — Single entry point.
Starts the FastAPI API server.

Usage:
    python run.py
    python run.py --seed       (seed database with default data first)
    python run.py --reset      (reset database, then seed, then start)
"""

import argparse
import asyncio
import sys

import uvicorn

from config.settings import get_settings


def main():
    parser = argparse.ArgumentParser(description="ASTRA Cybersecurity Simulator")
    parser.add_argument("--seed", action="store_true", help="Seed database with default data before starting")
    parser.add_argument("--reset", action="store_true", help="Reset database (WARNING: deletes all data)")
    parser.add_argument("--host", type=str, default=None, help="Override API host")
    parser.add_argument("--port", type=int, default=None, help="Override API port")
    args = parser.parse_args()

    settings = get_settings()
    host = args.host or settings.api_host
    port = args.port or settings.api_port

    # Handle --reset
    if args.reset:
        print("[ASTRA] Resetting database...")
        from db.engine import get_engine, init_db
        from db.models import Base

        async def _reset():
            engine = get_engine()
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            await init_db()

        asyncio.run(_reset())
        print("[ASTRA] Database reset complete.")
        args.seed = True  # Always seed after reset

    # Handle --seed
    if args.seed:
        print("[ASTRA] Seeding database...")
        from db.seed import seed_database
        asyncio.run(seed_database())
        print("[ASTRA] Seed complete.")

    # Start server
    uvicorn.run(
        "api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=settings.reload and settings.app_env == "development",
        log_level="info",
    )


if __name__ == "__main__":
    main()

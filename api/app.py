"""
FastAPI application factory — creates and configures the main API app.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import get_settings
from db.engine import init_db, close_db


# ---------------------------------------------------------------------------
# Lifespan — runs on startup/shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: init DB, print banner. Shutdown: close DB."""
    settings = get_settings()

    print(r"""
    ╔═╗╔═╗╔╦╗╦═╗╔═╗
    ╠═╣╚═╗ ║ ╠╦╝╠═╣
    ╩ ╩╚═╝ ╩ ╩╚═╩ ╩
    """)
    print(f"    v{settings.version} | {settings.app_env}")
    print(f"    API:       http://localhost:{settings.api_port}")
    print(f"    API Docs:  http://localhost:{settings.api_port}/docs")
    print(f"    Dashboard: http://localhost:{settings.dashboard_port}")
    print()

    # Init database
    await init_db()

    yield

    # Cleanup
    await close_db()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="AI-driven cybersecurity training simulator",
        lifespan=lifespan,
    )

    # CORS — allow dashboard to call API
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Tighten in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    _register_routers(app)

    return app


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------
def _register_routers(app: FastAPI) -> None:
    """Mount all API routers."""
    from api.routers.health import router as health_router
    from api.routers.sessions import router as sessions_router
    from api.routers.scenarios import router as scenarios_router
    from api.routers.detection import router as detection_router
    from api.routers.alerts import router as alerts_router

    app.include_router(health_router, tags=["Health"])
    app.include_router(sessions_router, prefix="/sessions", tags=["Sessions"])
    app.include_router(scenarios_router, prefix="/scenarios", tags=["Scenarios"])
    app.include_router(detection_router, prefix="/detection", tags=["Detection Rules"])
    app.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])

    # Block 2 (your friend's attack router)
    try:
        from api.routers.attacks import router as attacks_router
        app.include_router(attacks_router, prefix="/attacks", tags=["Attacks"])
    except ImportError:
        pass

    # Future routers (uncomment when built):
    # from api.routers.logs import router as logs_router
    # from api.routers.reports import router as reports_router

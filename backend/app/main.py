"""ERROR-PANEL — FastAPI application entry point.

Lifespan: creates all DB tables on startup, seeds settings defaults.
Routers: /api/sources, /api/profiles, /api (sync), /api/quarantine,
         /api (tests, metrics), /api (analytics, ranking),
         /api (settings, logs, backup, export).
Health: GET /api/health
Static: frontend served at "/" after all API routers.
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .db import create_tables, seed_settings_defaults
from .api.sources import router as sources_router
from .api.profiles import router as profiles_router
from .api.sync import router as sync_router
from .api.security import router as quarantine_router
from .api.tests import router as tests_router
from .api.analytics import router as analytics_router
from .api.settings import router as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup and seed settings defaults."""
    await create_tables()
    await seed_settings_defaults()
    yield


app = FastAPI(
    title="ERROR-PANEL",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow all for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers FIRST (so /api/* takes priority)
app.include_router(sources_router)
app.include_router(profiles_router)
app.include_router(sync_router)
app.include_router(quarantine_router)
app.include_router(tests_router)
app.include_router(analytics_router)
app.include_router(settings_router)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "app": "ERROR-PANEL",
        "status": "online",
        "version": "1.0.0",
    }


# Mount frontend as static files AFTER all API routers
# Resolves frontend path robustly for both dev and PyInstaller
if getattr(sys, "frozen", False):
    _FRONTEND_DIR = Path(sys._MEIPASS) / "frontend"
else:
    _FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")

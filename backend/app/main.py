"""ERROR-PANEL — FastAPI application entry point.

Lifespan: creates all DB tables on startup, seeds settings defaults.
Routers: /api/sources, /api/profiles, /api (sync), /api/quarantine,
         /api (tests, metrics), /api (analytics, ranking),
         /api (settings, logs, backup, export).
Health: GET /api/health
Static: frontend served at "/" after all API routers.
"""

import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from backend.core.logger import logger

from .db import create_tables, seed_settings_defaults, close_db
from .api.sources import router as sources_router
from .api.profiles import router as profiles_router
from .api.sync import router as sync_router
from .api.security import router as quarantine_router
from .api.tests import router as tests_router
from .api.analytics import router as analytics_router
from .api.settings import router as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup, seed settings, and dispose engine on shutdown."""
    await create_tables()
    await seed_settings_defaults()
    yield
    await close_db()



class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        logger.info(f"{request.method} {request.url.path} - {response.status_code}")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter: 100 requests per minute per IP."""
    def __init__(self, app, max_requests=100, window_seconds=60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for static files
        if not request.url.path.startswith("/api"):
            return await call_next(request)
            
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        
        # Clean old requests
        self.requests[client_ip] = [t for t in self.requests[client_ip] if now - t < self.window]
        
        if len(self.requests[client_ip]) >= self.max_requests:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again later."})
            
        self.requests[client_ip].append(now)
        return await call_next(request)

app = FastAPI(
    title="ERROR-PANEL",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow all for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers FIRST (so /api/* takes priority)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(RateLimitMiddleware)
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
from backend.core.paths import BASE_DIR

from pathlib import Path
import sys
import time
from collections import defaultdict

# Smart frontend path calculation
if getattr(sys, "frozen", False):
    # PyInstaller: frontend is bundled in _MEIPASS
    _FRONTEND_DIR = Path(sys._MEIPASS) / "frontend"
else:
    # Development: go from backend/app to root/frontend
    # __file__ = backend/app/main.py
    # parent = backend/app
    # parent.parent = backend
    # parent.parent.parent = ERROR-PANEL (root)
    _FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")



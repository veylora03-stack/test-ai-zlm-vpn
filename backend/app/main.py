"""
ERROR-PANEL — FastAPI application entry point.
Lifespan: creates all DB tables on startup, disposes engine on shutdown.
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

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from backend.core.logger import logger
from backend.middleware.auth import APITokenMiddleware, API_TOKEN
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
    """Create database tables on startup, dispose engine on shutdown."""
    await create_tables()
    await seed_settings_defaults()
    yield
    await close_db()


app = FastAPI(
    title="ERROR-PANEL",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS — restricted to exact local origins ──────────────────
# Prevents CSRF from malicious browser tabs targeting localhost API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-API-Token"],
)


# ── Rate Limiting Middleware ──────────────────────────────────
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter: 100 requests per minute per IP."""
    def __init__(self, app, max_requests=100, window_seconds=60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean up old timestamps for this IP
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if now - t < self.window
        ]

        # Memory Leak Fix: Remove IP key if list is empty
        if not self.requests[client_ip]:
            del self.requests[client_ip]

        if len(self.requests.get(client_ip, [])) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."}
            )

        self.requests[client_ip].append(now)
        return await call_next(request)


# ── Request Logging Middleware ────────────────────────────────
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        logger.info(f"{request.method} {request.url.path} - {response.status_code}")
        return response


app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestLoggingMiddleware)

# ── Authentication Middleware ──────────────────────────────────
app.add_middleware(APITokenMiddleware)


# ── Token endpoint for frontend ──────────────────────────────────
# ── Token endpoint (only accessible from localhost) ──────────────────────
@app.get("/api/token")
async def get_token(request: Request):
    client_host = request.client.host if request.client else "unknown"
    if client_host not in ["127.0.0.1", "::1", "localhost"]:
        raise HTTPException(status_code=403, detail="Forbidden: token only available locally")
    return {"token": API_TOKEN}

# ── Mount API routers FIRST (so /api/* takes priority) ────────
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


# ── Mount frontend as static files AFTER all API routers ──────
if getattr(sys, "frozen", False):
    _FRONTEND_DIR = Path(sys._MEIPASS) / "frontend"
else:
    _FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")






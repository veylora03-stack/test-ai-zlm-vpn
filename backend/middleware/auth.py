import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
import os

API_TOKEN = os.environ.get("ERROR_PANEL_TOKEN", secrets.token_urlsafe(32))

class APITokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # مسیرهای عمومی (مستندات و وضعیت)
        if request.url.path.startswith("/docs") or request.url.path.startswith("/redoc") or request.url.path.startswith("/openapi.json") or request.url.path == "/":
            return await call_next(request)
        # مسیر سلامت (برای بررسی اجرا)
        if request.url.path == "/health":
            return await call_next(request)
            
        token = request.headers.get("X-API-Token")
        if not token or token != API_TOKEN:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized: Invalid or missing API Token"})
        return await call_next(request)




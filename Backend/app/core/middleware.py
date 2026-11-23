"""Request ID, security headers and logging middleware."""

from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import new_request_id, request_id_var

logger = logging.getLogger("penpal.request")

SENSITIVE_PREFIXES = ("/api/v1/auth", "/api/v1/users", "/api/v1/findings", "/api/v1/ai")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id") or new_request_id()
        request_id = "".join(ch for ch in request_id if ch.isalnum() or ch in "-_")[:64]
        request_id_var.set(request_id or new_request_id())
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            logger.info(
                "%s %s -> %.1fms",
                request.method,
                request.url.path,
                elapsed_ms,
            )
        response.headers["X-Request-ID"] = request_id_var.get()
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if request.url.path.startswith(
            ("/api/v1/auth", "/api/v1/users", "/api/v1/findings", "/api/v1/ai", "/api/v1/reports")
        ):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

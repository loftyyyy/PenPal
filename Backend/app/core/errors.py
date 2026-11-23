"""Structured application errors and FastAPI exception handlers."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class AppError(Exception):
    """An expected failure with a stable machine-readable code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


class NotFoundError(AppError):
    def __init__(self, entity: str, entity_id: Any) -> None:
        super().__init__(404, "not_found", f"{entity} {entity_id} was not found")


class ForbiddenError(AppError):
    def __init__(self, message: str, details: Any = None) -> None:
        super().__init__(403, "forbidden", message, details)


class ConflictError(AppError):
    def __init__(self, message: str, details: Any = None) -> None:
        super().__init__(409, "conflict", message, details)


class ScopeViolationError(AppError):
    def __init__(self, message: str, reasons: list[str]) -> None:
        super().__init__(403, "scope_violation", message, {"reasons": reasons})


def _error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=_error_body(
                "validation_error",
                "Request validation failed",
                [
                    {
                        "loc": [str(part) for part in error.get("loc", [])],
                        "msg": error.get("msg", ""),
                        "type": error.get("type", ""),
                    }
                    for error in exc.errors()
                ],
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = f"http_{exc.status_code}"
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(code, detail),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error: %s", exc)
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error", "Internal server error"),
        )

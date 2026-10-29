"""Exception handlers that render every error as the standard envelope (DESIGN.md §14.2)."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from mizar.core.errors import ErrorCode, MizarError, error_envelope

log = logging.getLogger(__name__)


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


async def _mizar_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, MizarError)
    if exc.http_status >= 500:
        log.error(
            "%s: %s",
            exc.code.value,
            exc.message,
            extra={"request_id": _request_id(request), "error_code": exc.code.value},
        )
    return JSONResponse(
        error_envelope(exc.code, exc.message, _request_id(request), exc.details),
        status_code=exc.http_status,
    )


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    # Echo location and reason only: the offending input may be large or hostile.
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg"), "type": err.get("type")}
        for err in exc.errors()
    ]
    return JSONResponse(
        error_envelope(
            ErrorCode.VALIDATION_ERROR,
            "The request is invalid.",
            _request_id(request),
            {"errors": errors},
        ),
        status_code=422,
    )


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = {404: ErrorCode.NOT_FOUND, 405: ErrorCode.METHOD_NOT_ALLOWED}.get(
        exc.status_code, ErrorCode.HTTP_ERROR
    )
    message = exc.detail if isinstance(exc.detail, str) else "HTTP error."
    return JSONResponse(
        error_envelope(code, message, _request_id(request)),
        status_code=exc.status_code,
        headers=exc.headers,
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(MizarError, _mizar_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)

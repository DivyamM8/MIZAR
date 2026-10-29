"""Local-access guard and security headers (DESIGN.md §15).

Pure ASGI middleware so it also wraps responses for unhandled exceptions:
- assigns a request ID,
- rejects requests whose Host header is not loopback (DNS rebinding),
- rejects cross-origin browser requests,
- requires the per-launch API token on state-changing /api requests,
- adds security headers to every response,
- turns unhandled exceptions into an INTERNAL_ERROR envelope without stack traces.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Iterable

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mizar.core.errors import ErrorCode, default_http_status, error_envelope
from mizar.core.ids import new_request_id

log = logging.getLogger(__name__)

TOKEN_HEADER = "x-mizar-token"  # noqa: S105 (header name, not a secret)
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _host_without_port(host_header: str) -> str:
    host = host_header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.split(":", 1)[0]


class LocalGuardMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Iterable[str],
        allowed_origins: Iterable[str],
        api_token: str,
    ) -> None:
        if len(api_token) < 32:
            raise ValueError("api_token must be at least 32 characters")
        self.app = app
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.allowed_origins = frozenset(allowed_origins)
        self.api_token = api_token

    def _reject(self, scope: Scope) -> tuple[ErrorCode, str] | None:
        headers = Headers(scope=scope)
        if _host_without_port(headers.get("host", "")) not in self.allowed_hosts:
            return ErrorCode.HOST_NOT_ALLOWED, "Host header is not an allowed local address."
        origin = headers.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            return ErrorCode.ORIGIN_NOT_ALLOWED, "Cross-origin requests are not allowed."
        if scope["method"] in UNSAFE_METHODS and scope["path"].startswith("/api/"):
            token = headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(token.encode(), self.api_token.encode()):
                return ErrorCode.AUTH_TOKEN_INVALID, "Missing or invalid API token."
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = new_request_id()
        scope.setdefault("state", {})["request_id"] = request_id
        is_api = scope["path"].startswith("/api/")
        response_started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                headers["X-Request-ID"] = request_id
                if is_api:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        rejection = self._reject(scope)
        if rejection is not None:
            code, message = rejection
            log.warning("request rejected: %s", code.value, extra={"request_id": request_id})
            response = JSONResponse(
                error_envelope(code, message, request_id),
                status_code=default_http_status(code),
            )
            await response(scope, receive, send_with_headers)
            return

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            log.exception("unhandled error", extra={"request_id": request_id})
            if response_started:
                raise
            response = JSONResponse(
                error_envelope(
                    ErrorCode.INTERNAL_ERROR,
                    "An internal error occurred. See the application log for this request ID.",
                    request_id,
                ),
                status_code=500,
            )
            await response(scope, receive, send_with_headers)

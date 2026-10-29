"""Request-local Orca metadata; never pass the private header to upstream code."""

import re
from contextvars import ContextVar

from starlette.types import ASGIApp, Receive, Scope, Send

orca_terminal_handle: ContextVar[str | None] = ContextVar("orca_terminal_handle", default=None)
HEADER = b"x-orca-terminal-handle"


def normalize_handle(value: str | None) -> str | None:
    if value and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", value):
        return value
    return None


class OrcaTerminalMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        values = [value for name, value in scope.get("headers", []) if name.lower() == HEADER]
        handle = normalize_handle(values[0].decode("latin-1")) if len(values) == 1 else None
        # Receive wrappers and downstream handlers must share request state.
        scope.setdefault("state", {})
        scope = dict(scope)
        scope["headers"] = [(name, value) for name, value in scope.get("headers", []) if name.lower() != HEADER]
        token = orca_terminal_handle.set(handle)
        try:
            await self.app(scope, receive, send)
        finally:
            orca_terminal_handle.reset(token)

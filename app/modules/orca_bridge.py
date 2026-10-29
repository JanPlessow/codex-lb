"""Authenticated local bridge to Orca's terminal commands."""

import asyncio
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.auth.dependencies import require_dashboard_admin_access
from app.core.middleware.orca_terminal import normalize_handle

router = APIRouter(prefix="/api/orca", tags=["dashboard"], dependencies=[Depends(require_dashboard_admin_access)])
COMMAND_TIMEOUT_SECONDS = 10


class TerminalRequest(BaseModel):
    handle: str


async def _terminal_command(action: str, handle: str) -> None:
    try:
        process = await asyncio.create_subprocess_exec(
            "orca",
            "terminal",
            action,
            "--terminal",
            handle,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as exc:
        raise HTTPException(503, "Orca is unavailable") from exc
    try:
        await asyncio.wait_for(process.wait(), timeout=COMMAND_TIMEOUT_SECONDS)
    except (TimeoutError, asyncio.CancelledError) as exc:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise HTTPException(503, "Orca did not respond in time") from exc
    if process.returncode:
        raise HTTPException(404, "Terminal is stale or unavailable")


@router.post("/terminal/switch")
async def switch_terminal(req: TerminalRequest, request: Request) -> dict[str, bool]:
    try:
        local = request.client is not None and ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if not local:
        raise HTTPException(403, "Local access required")
    if normalize_handle(req.handle) is None:
        raise HTTPException(400, "Invalid terminal handle")
    await _terminal_command("show", req.handle)
    await _terminal_command("switch", req.handle)
    return {"ok": True}

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.auth.dependencies import (
    require_dashboard_admin_access,
    set_dashboard_error_format,
    validate_dashboard_session,
)
from app.core.clients.oauth import OAuthError
from app.core.socket_peer import raw_socket_peer_host
from app.core.upstream_proxy.resolver import UpstreamProxyRouteError
from app.dependencies import LocalBrowserContext, get_local_browser_context
from app.modules.dashboard_auth.service import DASHBOARD_SESSION_COOKIE, get_dashboard_session_store
from app.modules.local_browser.runtime import capability_enabled
from app.modules.local_browser.schemas import (
    BrowserActionResponse,
    BrowserCapabilities,
    BrowserFlowRequest,
    BrowserStartRequest,
    BrowserStartResponse,
)

router = APIRouter(
    prefix="/api/local-browser",
    tags=["dashboard"],
    dependencies=[Depends(validate_dashboard_session), Depends(set_dashboard_error_format)],
)


async def require_browser_access(request: Request) -> None:
    await require_dashboard_admin_access(request)
    state = get_dashboard_session_store().get(request.cookies.get(DASHBOARD_SESSION_COOKIE))
    if state is None or not state.password_verified:
        raise HTTPException(403, "Sign in to the dashboard before opening an account browser")
    peer = raw_socket_peer_host(request)
    try:
        local_peer = peer is not None and ip_address(peer).is_loopback
    except ValueError:
        local_peer = False
    try:
        host = urlsplit("//" + request.headers.get("host", ""))
        hostname = host.hostname
    except ValueError:
        hostname = None
    origin = request.headers.get("origin")
    expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
    if (
        not local_peer
        or hostname not in {"127.0.0.1", "localhost", "::1"}
        or origin != expected
        or request.headers.get("x-codex-lb-browser") != "1"
        or request.headers.get("sec-fetch-site") not in {None, "same-origin"}
        or any(key in request.headers for key in ("forwarded", "x-forwarded-for", "x-forwarded-host"))
    ):
        raise HTTPException(403, "Account browsers require the local dashboard on this Mac")


@router.get("/capabilities", response_model=BrowserCapabilities)
async def capabilities() -> BrowserCapabilities:
    return BrowserCapabilities(enabled=capability_enabled())


@router.post("/start", response_model=BrowserStartResponse, dependencies=[Depends(require_browser_access)])
async def start(
    request: BrowserStartRequest, context: LocalBrowserContext = Depends(get_local_browser_context)
) -> BrowserStartResponse:
    try:
        return await context.service.start(request)
    except OAuthError as exc:
        raise HTTPException(409, exc.message) from None
    except (UpstreamProxyRouteError, OSError):
        raise HTTPException(503, "The account browser or assigned proxy is unavailable") from None


@router.post("/reopen", response_model=BrowserStartResponse, dependencies=[Depends(require_browser_access)])
async def reopen(
    request: BrowserFlowRequest, context: LocalBrowserContext = Depends(get_local_browser_context)
) -> BrowserStartResponse:
    try:
        return await context.service.reopen(request.flow_id)
    except OAuthError as exc:
        raise HTTPException(409, exc.message) from None
    except (UpstreamProxyRouteError, OSError):
        raise HTTPException(503, "The account browser or assigned proxy is unavailable") from None


@router.post("/cancel", response_model=BrowserActionResponse, dependencies=[Depends(require_browser_access)])
async def cancel(
    request: BrowserFlowRequest, context: LocalBrowserContext = Depends(get_local_browser_context)
) -> BrowserActionResponse:
    try:
        await context.service.cancel(request.flow_id)
    except OAuthError as exc:
        raise HTTPException(409, exc.message) from None
    return BrowserActionResponse(status="canceled")

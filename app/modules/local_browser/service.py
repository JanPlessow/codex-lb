from __future__ import annotations

import socket
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients.oauth import build_authorization_url, pkce_challenge
from app.core.crypto import TokenEncryptor
from app.core.upstream_proxy.resolver import _resolve_pool, resolve_upstream_route
from app.core.utils.time import utcnow
from app.db.models import Account, BrowserOAuthFlow, BrowserPersona, OAuthFlowState
from app.modules.local_browser.repository import browser_error, managed_flow_route, route_fingerprint
from app.modules.local_browser.runtime import capability_enabled, get_browser_runtime
from app.modules.local_browser.schemas import BrowserStartRequest, BrowserStartResponse
from app.modules.oauth.repository import OAuthFlowRepository
from app.modules.oauth.service import OauthService


class BrowserService:
    def __init__(self, session: AsyncSession, oauth: OauthService) -> None:
        self.session = session
        self.oauth = oauth

    async def start(self, request: BrowserStartRequest) -> BrowserStartResponse:
        async with get_browser_runtime().flow_lock:
            return await self._start(request)

    async def _start(self, request: BrowserStartRequest) -> BrowserStartResponse:
        if not capability_enabled():
            raise browser_error("Local account browsers are not enabled on this Mac.")
        runtime = get_browser_runtime()
        async with runtime.lock:
            if request.account_id:
                account = await self.session.get(Account, request.account_id)
                if account is None:
                    raise browser_error("The selected account no longer exists.")
                label = account.email
                route = await resolve_upstream_route(self.session, account_id=account.id, operation="browser")
                persona = await self.session.scalar(
                    select(BrowserPersona).where(BrowserPersona.account_id == account.id)
                )
            else:
                label = "New account"
                persona = None
                route = (
                    None
                    if request.direct
                    else await _resolve_pool(
                        self.session,
                        pool_id=request.pool_id or "",
                        mode="account_bound",
                        account_id=None,
                        encryptor=None,
                    )
                )
            if not request.account_id and request.direct:
                inherited = await resolve_upstream_route(self.session, account_id=None, operation="browser")
                if inherited is not None:
                    raise browser_error(
                        "Direct enrollment is unavailable while a global proxy is enabled. Choose a proxy pool."
                    )
            fingerprint = await route_fingerprint(self.session, route)
            mode = "direct" if route is None else "proxy"
            if persona is None:
                reserved = set((await self.session.scalars(select(BrowserPersona.relay_port))).all())
                port = None
                for _ in range(100):
                    with socket.socket() as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        candidate = reservation.getsockname()[1]
                    if candidate not in reserved:
                        port = candidate
                        break
                if port is None:
                    raise browser_error("No browser listener port is available.")
                persona = BrowserPersona(
                    id=str(uuid.uuid4()),
                    account_id=request.account_id,
                    state="active" if request.account_id else "enrolling",
                    route_mode=mode,
                    route_fingerprint=fingerprint,
                    enrollment_pool_id=request.pool_id,
                    relay_port=port,
                )
                self.session.add(persona)
            elif persona.route_mode != mode:
                raise browser_error(
                    "This account's assigned connection disappeared or changed type. Restore it before signing in."
                )
            else:
                persona.route_fingerprint = fingerprint
            await self.session.commit()
            await self.session.refresh(persona)
            persona_id, persona_mode = persona.id, persona.route_mode
            # A repeated click resumes its pending flow instead of replacing it.
            pending = await self.session.scalar(
                select(OAuthFlowState)
                .join(BrowserOAuthFlow, BrowserOAuthFlow.flow_id == OAuthFlowState.flow_id)
                .where(
                    BrowserOAuthFlow.persona_id == persona.id,
                    BrowserOAuthFlow.route_fingerprint == fingerprint,
                    OAuthFlowState.status == "pending",
                    OAuthFlowState.expires_at > utcnow(),
                )
                .order_by(OAuthFlowState.created_at.desc())
                .limit(1)
            )
            pending_id = pending.flow_id if pending else None
            await self.session.rollback()
        if pending_id:
            return await self.reopen(pending_id)
        response = await self.oauth._start_browser_flow(intended_account_id=request.account_id, managed_browser=True)
        if response.method != "browser" or response.flow_id is None or response.authorization_url is None:
            raise browser_error("A local browser sign-in could not be prepared. Retry from the account.")
        self.session.add(
            BrowserOAuthFlow(flow_id=response.flow_id, persona_id=persona_id, route_fingerprint=fingerprint)
        )
        await self.session.commit()
        try:
            await runtime.launch(persona_id, response.authorization_url)
        except Exception:
            await self.cancel(response.flow_id)
            raise
        return BrowserStartResponse(
            **response.model_dump(exclude={"authorization_url"}),
            authorization_url=None,
            persona_id=persona_id,
            browser_label=label,
            route_mode="direct" if persona_mode == "direct" else "proxy",
        )

    async def reopen(self, flow_id: str) -> BrowserStartResponse:
        managed, _ = await managed_flow_route(flow_id)
        if not managed:
            raise browser_error("This is not an account browser sign-in.")
        binding = await self.session.get(BrowserOAuthFlow, flow_id)
        if binding is None:
            raise browser_error("Unknown browser flow.")
        persona = await self.session.get(BrowserPersona, binding.persona_id)
        record = await OAuthFlowRepository(self.session, TokenEncryptor()).get_by_flow_id(flow_id)
        if persona is None or record is None or not record.state_token or not record.code_verifier:
            raise browser_error("This browser sign-in has expired.")
        account = await self.session.get(Account, persona.account_id) if persona.account_id else None
        label = account.email if account else "New account"
        persona_id, mode = persona.id, persona.route_mode
        url = build_authorization_url(state=record.state_token, code_challenge=pkce_challenge(record.code_verifier))
        await self.session.rollback()
        await self.oauth.resume_browser_callback(flow_id)
        await get_browser_runtime().launch(persona_id, url)
        return BrowserStartResponse(
            method="browser",
            flow_id=flow_id,
            persona_id=persona_id,
            browser_label=label,
            route_mode="direct" if mode == "direct" else "proxy",
        )

    async def cancel(self, flow_id: str) -> None:
        binding = await self.session.get(BrowserOAuthFlow, flow_id)
        if binding is None:
            raise browser_error("Unknown browser flow.")
        flow = await self.session.get(OAuthFlowState, flow_id)
        if flow is not None and flow.status == "pending":
            flow.status = "error"
            flow.error_message = "Sign-in canceled. Start again from the account."
            flow.finished_at = utcnow()
        persona = await self.session.get(BrowserPersona, binding.persona_id)
        if persona is not None and persona.state == "enrolling":
            persona.state = "revoked"
        await self.session.commit()
        await get_browser_runtime().revalidate()

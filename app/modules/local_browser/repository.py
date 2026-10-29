from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients.oauth import OAuthError
from app.core.upstream_proxy.resolver import _resolve_pool, resolve_upstream_route
from app.core.upstream_proxy.types import ResolvedUpstreamRoute
from app.core.utils.time import to_utc_naive, utcnow
from app.db.models import Account, BrowserOAuthFlow, BrowserPersona, OAuthFlowState, ProxyEndpoint
from app.db.session import get_background_session


def browser_error(message: str) -> OAuthError:
    return OAuthError("local_browser_unavailable", message, status_code=409)


@dataclass(frozen=True, slots=True)
class PersonaRoute:
    persona_id: str
    port: int
    fingerprint: str
    route: ResolvedUpstreamRoute | None


async def route_fingerprint(session: AsyncSession, route: ResolvedUpstreamRoute | None) -> str:
    if route is None:
        return "direct"
    if route.fallbacks:
        raise browser_error("Account browsers require a proxy pool with exactly one active endpoint.")
    row = await session.get(ProxyEndpoint, route.endpoint_id)
    if row is None:
        raise browser_error("The assigned proxy endpoint no longer exists.")
    # Hash ciphertext rather than low-entropy plaintext credentials.
    value = [route.pool_id, row.id, row.scheme, row.host, row.port, row.username, (row.password_encrypted or b"").hex()]
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


async def resolve_persona(session: AsyncSession, persona: BrowserPersona) -> PersonaRoute:
    if persona.state == "active" and persona.account_id:
        if await session.get(Account, persona.account_id) is None:
            raise browser_error("The account no longer exists.")
        route = await resolve_upstream_route(session, account_id=persona.account_id, operation="browser")
    elif persona.state == "enrolling" and persona.account_id is None:
        route = (
            await resolve_upstream_route(session, account_id=None, operation="browser")
            if persona.enrollment_pool_id is None
            else await _resolve_pool(
                session, pool_id=persona.enrollment_pool_id, mode="account_bound", account_id=None, encryptor=None
            )
        )
    else:
        raise browser_error("This browser persona is no longer active.")
    if (route is None) != (persona.route_mode == "direct"):
        raise browser_error("The account's connection changed. Restore its assigned route before opening its browser.")
    fingerprint = await route_fingerprint(session, route)
    if fingerprint != persona.route_fingerprint:
        raise browser_error("The account's proxy changed. Reopen its browser from Codex LB to apply the new route.")
    return PersonaRoute(persona.id, persona.relay_port, fingerprint, route)


async def load_persona_route(persona_id: str) -> PersonaRoute:
    async with get_background_session() as session:
        persona = await session.get(BrowserPersona, persona_id)
        if persona is None:
            raise browser_error("Unknown browser persona.")
        if persona.state == "enrolling" and persona.enrollment_pool_id is None:
            pending = await session.scalar(
                select(OAuthFlowState.flow_id)
                .join(BrowserOAuthFlow, BrowserOAuthFlow.flow_id == OAuthFlowState.flow_id)
                .where(
                    BrowserOAuthFlow.persona_id == persona.id,
                    OAuthFlowState.status == "pending",
                    OAuthFlowState.expires_at > utcnow(),
                )
                .limit(1)
            )
            if pending is None:
                raise browser_error("The enrollment expired. Start Add account again.")
        return await resolve_persona(session, persona)


async def validate_managed_flow(session: AsyncSession, flow_id: str) -> tuple[BrowserPersona, PersonaRoute]:
    binding = await session.get(BrowserOAuthFlow, flow_id, populate_existing=True)
    if binding is None:
        raise browser_error("The browser route association is missing.")
    flow = await session.get(OAuthFlowState, flow_id, populate_existing=True)
    if flow is None or flow.status != "pending" or flow.expires_at is None or to_utc_naive(flow.expires_at) <= utcnow():
        raise browser_error("This browser sign-in has expired or finished.")
    persona = await session.get(BrowserPersona, binding.persona_id, populate_existing=True)
    if persona is None:
        raise browser_error("Unknown browser persona.")
    resolved = await resolve_persona(session, persona)
    if resolved.fingerprint != binding.route_fingerprint:
        raise browser_error("The connection changed during sign-in. Start again from the account.")
    if flow.intended_account_id != persona.account_id:
        raise browser_error("The sign-in no longer belongs to this account.")
    return persona, resolved


async def managed_flow_route(flow_id: str) -> tuple[bool, ResolvedUpstreamRoute | None]:
    async with get_background_session() as session:
        if await session.get(BrowserOAuthFlow, flow_id) is None:
            return False, None
        _, resolved = await validate_managed_flow(session, flow_id)
        return True, resolved.route

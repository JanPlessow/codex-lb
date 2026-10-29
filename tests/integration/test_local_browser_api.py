from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.clients.oauth import OAuthTokens
from app.core.config.settings import get_settings
from app.core.crypto import TokenEncryptor
from app.core.utils.time import utcnow
from app.db.models import (
    Account,
    AccountProxyBinding,
    AccountStatus,
    BrowserPersona,
    DashboardSettings,
    OAuthFlowState,
    ProxyEndpoint,
    ProxyPool,
    ProxyPoolMember,
)
from app.db.session import SessionLocal
from app.modules.local_browser import runtime as browser_runtime
from app.modules.local_browser.repository import managed_flow_route
from app.modules.oauth import service as oauth_module

REAL_CALLBACK_START = oauth_module.OAuthCallbackServer.start
REAL_CALLBACK_STOP = oauth_module.OAuthCallbackServer.stop


@pytest_asyncio.fixture
async def browser_client(app_instance, monkeypatch, tmp_path):
    settings = get_settings()
    monkeypatch.setattr(settings, "local_browser_enabled", True)
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(browser_runtime, "capability_enabled", lambda: True)
    monkeypatch.setattr("app.modules.local_browser.api.capability_enabled", lambda: True)
    monkeypatch.setattr("app.modules.local_browser.service.capability_enabled", lambda: True)
    runtime = browser_runtime.BrowserRuntime()
    monkeypatch.setattr(browser_runtime, "_runtime", runtime)
    launch = AsyncMock()
    monkeypatch.setattr(runtime, "launch", launch)
    monkeypatch.setattr(oauth_module.OAuthCallbackServer, "start", AsyncMock())
    monkeypatch.setattr(oauth_module.OAuthCallbackServer, "stop", AsyncMock())
    monkeypatch.setattr(oauth_module, "_OAUTH_STORE", oauth_module.OAuthStateStore())
    async with app_instance.router.lifespan_context(app_instance):
        async with AsyncClient(transport=ASGITransport(app=app_instance), base_url="http://127.0.0.1") as client:
            response = await client.post(
                "/api/dashboard-auth/password/setup", json={"password": "browser-test-password"}
            )
            assert response.status_code == 200, response.text
            client.headers.update({"Origin": "http://127.0.0.1", "X-Codex-LB-Browser": "1"})
            yield client, launch, runtime
    await oauth_module._OAUTH_STORE.reset()


async def seed_account(account_id="seat-a", *, proxy=True):
    encryptor = TokenEncryptor()
    async with SessionLocal() as session:
        account = Account(
            id=account_id,
            email=f"{account_id}@example.com",
            chatgpt_account_id="workspace",
            chatgpt_user_id=account_id,
            access_token_encrypted=encryptor.encrypt("test-access"),
            refresh_token_encrypted=encryptor.encrypt("test-refresh"),
            id_token_encrypted=encryptor.encrypt(jwt(account_id)),
            plan_type="plus",
            status=AccountStatus.ACTIVE,
            last_refresh=utcnow(),
        )
        session.add(account)
        if proxy:
            session.add(
                ProxyEndpoint(
                    id="endpoint",
                    name="Synthetic",
                    scheme="socks5h",
                    host="127.0.0.1",
                    port=9,
                    username="synthetic-user",
                    password_encrypted=encryptor.encrypt("synthetic-password"),
                    is_active=True,
                )
            )
            session.add(ProxyPool(id="pool", name="Synthetic pool", is_active=True))
            await session.flush()
            session.add(
                ProxyPoolMember(id="member", pool_id="pool", endpoint_id="endpoint", is_active=True, sort_order=0)
            )
            session.add(AccountProxyBinding(account_id=account_id, pool_id="pool", is_active=True))
        await session.commit()


def jwt(seat="new-seat"):
    payload = {
        "sub": seat,
        "email": f"{seat}@example.com",
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "workspace",
            "chatgpt_user_id": seat,
            "chatgpt_plan_type": "plus",
        },
    }
    return "header." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".sig"


async def complete_flow(client, launch, monkeypatch, seat="new-seat"):
    url = launch.call_args.args[1]
    state = parse_qs(urlsplit(url).query)["state"][0]
    exchange = AsyncMock(
        return_value=OAuthTokens(access_token="new-access", refresh_token="new-refresh", id_token=jwt(seat))
    )
    monkeypatch.setattr(oauth_module, "exchange_authorization_code", exchange)
    response = await client.post(
        "/api/oauth/manual-callback",
        json={"callbackUrl": f"http://localhost:1455/auth/callback?state={state}&code=synthetic"},
    )
    return response, exchange


@pytest.mark.asyncio
async def test_local_browser_capability_is_explicitly_disabled_by_default(async_client):
    response = await async_client.get("/api/local-browser/capabilities")
    assert response.status_code == 200
    assert response.json()["enabled"] is False


@pytest.mark.asyncio
async def test_local_browser_start_requires_real_session_even_on_loopback(async_client):
    response = await async_client.post(
        "/api/local-browser/start",
        json={"accountId": "unknown"},
        headers={"Origin": "http://testserver", "X-Codex-LB-Browser": "1"},
    )
    assert response.status_code in {401, 403}


@pytest.mark.asyncio
async def test_account_click_launches_owned_profile_and_reuses_pending_flow(browser_client):
    client, launch, _ = browser_client
    await seed_account()
    first = await client.post("/api/local-browser/start", json={"accountId": "seat-a"})
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["authorizationUrl"] is None
    assert body["routeMode"] == "proxy"
    assert "synthetic-password" not in first.text
    assert launch.call_args.args[0] == body["personaId"]
    repeated = await client.post("/api/local-browser/start", json={"accountId": "seat-a"})
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["flowId"] == body["flowId"]
    managed, route = await managed_flow_route(body["flowId"])
    assert route is not None
    assert managed and route.endpoint_id == "endpoint" and not route.fallbacks
    reopened = await client.post("/api/local-browser/reopen", json={"flowId": body["flowId"]})
    assert reopened.status_code == 200
    assert launch.call_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,value",
    [
        ("Origin", "https://evil.example"),
        ("Host", "evil.example"),
        ("X-Codex-LB-Browser", "0"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("Sec-Fetch-Site", "cross-site"),
    ],
)
async def test_native_launch_rejects_cross_origin_and_forwarded_requests(browser_client, header, value):
    client, launch, _ = browser_client
    response = await client.post("/api/local-browser/start", json={"direct": True}, headers={header: value})
    assert response.status_code in {401, 403}
    launch.assert_not_called()


@pytest.mark.asyncio
async def test_enrollment_requires_explicit_route_and_rejects_arbitrary_launch_arguments(browser_client):
    client, launch, _ = browser_client
    for body in ({}, {"direct": True, "poolId": "pool"}, {"direct": True, "url": "https://evil.example"}):
        assert (await client.post("/api/local-browser/start", json=body)).status_code == 422
    launch.assert_not_called()


@pytest.mark.asyncio
async def test_changed_or_disabled_binding_blocks_browser_and_exchange(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    response = await client.post("/api/local-browser/start", json={"accountId": "seat-a"})
    flow_id = response.json()["flowId"]
    async with SessionLocal() as session:
        binding = await session.scalar(select(AccountProxyBinding))
        assert binding is not None
        binding.is_active = False
        await session.commit()
    assert (await client.post("/api/local-browser/reopen", json={"flowId": flow_id})).status_code == 409
    result, exchange = await complete_flow(client, launch, monkeypatch, "seat-a")
    assert result.json()["status"] == "error"
    exchange.assert_not_called()
    assert (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).status_code == 409


@pytest.mark.asyncio
async def test_multi_endpoint_persona_is_rejected_before_launch(browser_client):
    client, launch, _ = browser_client
    await seed_account()
    async with SessionLocal() as session:
        session.add(ProxyEndpoint(id="second", name="Second", scheme="http", host="127.0.0.1", port=8, is_active=True))
        await session.flush()
        session.add(
            ProxyPoolMember(id="second-member", pool_id="pool", endpoint_id="second", is_active=True, sort_order=1)
        )
        await session.commit()
    assert (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).status_code == 409
    launch.assert_not_called()
    async with SessionLocal() as session:
        assert (await session.scalars(select(OAuthFlowState))).all() == []


@pytest.mark.asyncio
async def test_proxy_enrollment_activates_account_with_binding_and_persona(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    response = await client.post("/api/local-browser/start", json={"poolId": "pool"})
    assert response.status_code == 200, response.text
    result, exchange = await complete_flow(client, launch, monkeypatch)
    assert result.json()["status"] == "success", result.text
    assert exchange.call_args.kwargs["route"].endpoint_id == "endpoint"
    assert exchange.call_args.kwargs["allow_direct_egress"] is False
    async with SessionLocal() as session:
        account = await session.scalar(select(Account).where(Account.email == "new-seat@example.com"))
        assert account is not None
        persona = await session.get(BrowserPersona, response.json()["personaId"])
        assert persona is not None
        binding = await session.scalar(select(AccountProxyBinding).where(AccountProxyBinding.account_id == account.id))
        assert binding is not None
        assert account.status == AccountStatus.ACTIVE
        assert binding.pool_id == "pool"
        assert persona.account_id == account.id and persona.state == "active"


@pytest.mark.asyncio
async def test_duplicate_enrollment_preserves_existing_credentials(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    response = await client.post("/api/local-browser/start", json={"direct": True})
    assert response.status_code == 200
    result, _ = await complete_flow(client, launch, monkeypatch, "seat-a")
    assert result.json()["status"] == "error"
    async with SessionLocal() as session:
        account = await session.get(Account, "seat-a")
        assert account is not None
        assert TokenEncryptor().decrypt(account.refresh_token_encrypted) == "test-refresh"
        assert len((await session.scalars(select(Account))).all()) == 1


@pytest.mark.asyncio
async def test_cancel_revokes_enrollment_and_prevents_reopen(browser_client):
    client, _, _ = browser_client
    response = await client.post("/api/local-browser/start", json={"direct": True})
    flow_id = response.json()["flowId"]
    assert (await client.post("/api/local-browser/cancel", json={"flowId": flow_id})).status_code == 200
    assert (await client.post("/api/local-browser/reopen", json={"flowId": flow_id})).status_code == 409
    async with SessionLocal() as session:
        persona = await session.get(BrowserPersona, response.json()["personaId"])
        assert persona is not None and persona.state == "revoked"


@pytest.mark.asyncio
async def test_targeted_login_keeps_wrong_seat_protection(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    assert (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).status_code == 200
    result, _ = await complete_flow(client, launch, monkeypatch, "wrong-seat")
    assert result.json()["status"] == "error"
    async with SessionLocal() as session:
        account = await session.get(Account, "seat-a")
        assert account is not None
        assert TokenEncryptor().decrypt(account.refresh_token_encrypted) == "test-refresh"


@pytest.mark.asyncio
async def test_targeted_login_succeeds_without_changing_route_or_persona(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    started = (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).json()
    result, exchange = await complete_flow(client, launch, monkeypatch, "seat-a")
    assert result.json()["status"] == "success", result.text
    assert exchange.call_args.kwargs["route"].endpoint_id == "endpoint"
    async with SessionLocal() as session:
        account = await session.get(Account, "seat-a")
        assert account is not None
        assert TokenEncryptor().decrypt(account.refresh_token_encrypted) == "new-refresh"
        persona = await session.get(BrowserPersona, started["personaId"])
        assert persona is not None and persona.account_id == "seat-a"
        binding = await session.scalar(select(AccountProxyBinding).where(AccountProxyBinding.account_id == "seat-a"))
        assert binding is not None and binding.pool_id == "pool"


@pytest.mark.asyncio
async def test_credential_edit_after_restart_blocks_pending_flow(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    started = (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).json()
    monkeypatch.setattr(oauth_module, "_OAUTH_STORE", oauth_module.OAuthStateStore())
    async with SessionLocal() as session:
        endpoint = await session.get(ProxyEndpoint, "endpoint")
        assert endpoint is not None
        endpoint.password_encrypted = TokenEncryptor().encrypt("replacement-password")
        await session.commit()
    result, exchange = await complete_flow(client, launch, monkeypatch, "seat-a")
    assert result.json()["status"] == "error"
    exchange.assert_not_called()
    assert (await client.post("/api/local-browser/reopen", json={"flowId": started["flowId"]})).status_code == 409


@pytest.mark.asyncio
async def test_direct_enrollment_cannot_disagree_with_global_proxy_route(browser_client):
    client, launch, _ = browser_client
    await seed_account()
    async with SessionLocal() as session:
        settings = await session.get(DashboardSettings, 1)
        assert settings is not None
        settings.upstream_proxy_routing_enabled = True
        settings.upstream_proxy_default_pool_id = "pool"
        await session.commit()
    response = await client.post("/api/local-browser/start", json={"direct": True})
    assert response.status_code == 409
    launch.assert_not_called()


@pytest.mark.asyncio
async def test_route_edit_during_exchange_prevents_credential_commit(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    await client.post("/api/local-browser/start", json={"accountId": "seat-a"})
    state = parse_qs(urlsplit(launch.call_args.args[1]).query)["state"][0]
    exchanged = []

    async def exchange(**kwargs):
        exchanged.append(True)
        async with SessionLocal() as session:
            binding = await session.scalar(
                select(AccountProxyBinding).where(AccountProxyBinding.account_id == "seat-a")
            )
            assert binding is not None
            binding.is_active = False
            await session.commit()
        return OAuthTokens(access_token="new-access", refresh_token="new-refresh", id_token=jwt("seat-a"))

    monkeypatch.setattr(oauth_module, "exchange_authorization_code", exchange)
    result = await client.post(
        "/api/oauth/manual-callback",
        json={"callbackUrl": f"http://localhost:1455/auth/callback?state={state}&code=synthetic"},
    )
    assert result.json()["status"] == "error"
    assert exchanged == [True]
    async with SessionLocal() as session:
        account = await session.get(Account, "seat-a")
        assert account is not None
        assert TokenEncryptor().decrypt(account.refresh_token_encrypted) == "test-refresh"


@pytest.mark.asyncio
async def test_reopen_after_restart_restores_callback_listener(browser_client, monkeypatch):
    client, _, _ = browser_client
    await seed_account()
    started = (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).json()
    listener_start = oauth_module.OAuthCallbackServer.start
    assert isinstance(listener_start, AsyncMock)
    assert listener_start.await_count == 1
    monkeypatch.setattr(oauth_module, "_OAUTH_STORE", oauth_module.OAuthStateStore())
    response = await client.post("/api/local-browser/reopen", json={"flowId": started["flowId"]})
    assert response.status_code == 200
    assert listener_start.await_count == 2


@pytest.mark.asyncio
async def test_resume_restores_real_http_callback_and_finishes_same_flow(browser_client, monkeypatch, unused_tcp_port):
    client, launch, _ = browser_client
    await seed_account()
    started = (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).json()
    state = parse_qs(urlsplit(launch.call_args.args[1]).query)["state"][0]
    monkeypatch.setattr(oauth_module, "_OAUTH_STORE", oauth_module.OAuthStateStore())
    monkeypatch.setattr(oauth_module, "OAUTH_CALLBACK_PORT", unused_tcp_port)
    monkeypatch.setattr(oauth_module.OAuthCallbackServer, "start", REAL_CALLBACK_START)
    monkeypatch.setattr(oauth_module.OAuthCallbackServer, "stop", REAL_CALLBACK_STOP)
    exchange = AsyncMock(
        return_value=OAuthTokens(access_token="new-access", refresh_token="new-refresh", id_token=jwt("seat-a"))
    )
    monkeypatch.setattr(oauth_module, "exchange_authorization_code", exchange)
    response = await client.post("/api/local-browser/reopen", json={"flowId": started["flowId"]})
    assert response.status_code == 200
    assert parse_qs(urlsplit(launch.call_args.args[1]).query)["state"][0] == state
    async with AsyncClient(trust_env=False) as browser:
        completed = await browser.get(
            f"http://127.0.0.1:{unused_tcp_port}/auth/callback", params={"state": state, "code": "synthetic"}
        )
    assert completed.status_code == 200
    assert exchange.await_count == 1
    async with SessionLocal() as session:
        account = await session.get(Account, "seat-a")
        assert account is not None
        assert TokenEncryptor().decrypt(account.refresh_token_encrypted) == "new-refresh"


@pytest.mark.asyncio
async def test_resume_port_conflict_preserves_flow_and_does_not_launch(browser_client, monkeypatch):
    client, launch, _ = browser_client
    await seed_account()
    started = (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).json()
    monkeypatch.setattr(oauth_module, "_OAUTH_STORE", oauth_module.OAuthStateStore())
    monkeypatch.setattr(oauth_module.OAuthCallbackServer, "start", AsyncMock(side_effect=OSError("address in use")))
    response = await client.post("/api/local-browser/reopen", json={"flowId": started["flowId"]})
    assert response.status_code == 409
    assert launch.await_count == 1
    async with SessionLocal() as session:
        flow = await session.get(OAuthFlowState, started["flowId"])
        assert flow is not None and flow.status == "pending"


@pytest.mark.asyncio
async def test_remote_authenticated_peer_cannot_launch(browser_client, app_instance):
    client, launch, _ = browser_client
    async with AsyncClient(
        transport=ASGITransport(app=app_instance, client=("203.0.113.7", 12345)),
        base_url="http://127.0.0.1",
        cookies=client.cookies,
        headers=client.headers,
    ) as remote:
        response = await remote.post("/api/local-browser/start", json={"direct": True})
    assert response.status_code in {401, 403}
    launch.assert_not_called()


@pytest.mark.asyncio
async def test_resume_waits_for_shutdown_started_during_durable_hydration(browser_client, monkeypatch):
    import asyncio

    from app.modules.accounts.repository import AccountsRepository

    client, _, _ = browser_client
    await seed_account()
    started = (await client.post("/api/local-browser/start", json={"accountId": "seat-a"})).json()
    store = oauth_module.OAuthStateStore()
    monkeypatch.setattr(oauth_module, "_OAUTH_STORE", store)
    stop_entered = asyncio.Event()
    release_stop = asyncio.Event()
    original_hydrate = oauth_module.OauthService._reconcile_flow_from_durable
    finish_tasks = []

    class StoppingServer(oauth_module.OAuthCallbackServer):
        def __init__(self):
            pass

        async def stop(self):
            stop_entered.set()
            await release_stop.wait()

    async def hydrate_with_shutdown(service, **kwargs):
        store._callback_server = StoppingServer()
        finish_tasks.append(asyncio.create_task(service._stop_callback_server_if_idle()))
        await stop_entered.wait()
        return await original_hydrate(service, **kwargs)

    monkeypatch.setattr(oauth_module.OauthService, "_reconcile_flow_from_durable", hydrate_with_shutdown)
    async with SessionLocal() as session:
        service = oauth_module.OauthService(AccountsRepository(session), store=store)
        resuming = asyncio.create_task(service.resume_browser_callback(started["flowId"]))
        try:
            await stop_entered.wait()
            await asyncio.sleep(0.05)
            assert not resuming.done(), "Resume accepted a stopping callback listener"
            release_stop.set()
            await asyncio.wait_for(resuming, 1)
            await asyncio.gather(*finish_tasks)
            assert store._callback_server is not None
            assert store._callback_server_stop_task is None
            assert isinstance(oauth_module.OAuthCallbackServer.start, AsyncMock)
            assert oauth_module.OAuthCallbackServer.start.await_count == 2
        finally:
            release_stop.set()
            await asyncio.gather(resuming, *finish_tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_manager_restart_restores_distinct_persistent_persona_ports(browser_client, monkeypatch):
    client, _, original = browser_client
    await seed_account("direct-a", proxy=False)
    await seed_account("direct-b", proxy=False)
    for account_id in ("direct-a", "direct-b"):
        assert (await client.post("/api/local-browser/start", json={"accountId": account_id})).status_code == 200
    async with SessionLocal() as session:
        saved = {row.id: row.relay_port for row in (await session.scalars(select(BrowserPersona))).all()}
    assert len(saved) == 2 and len(set(saved.values())) == 2
    await original.stop()
    restored = browser_runtime.BrowserRuntime()
    monkeypatch.setattr(browser_runtime, "_runtime", restored)
    try:
        await restored.start()
        assert set(restored.listeners) == set(saved)
        for persona_id, port in saved.items():
            listener = restored.listeners[persona_id]
            assert listener.server is not None
            assert listener.server.sockets[0].getsockname() == ("127.0.0.1", port)
    finally:
        await restored.stop()

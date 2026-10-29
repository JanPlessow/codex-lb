from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from app.core import pool_serving


@pytest.mark.asyncio
async def test_proxy_rejects_missing_and_changed_measured_identity(monkeypatch):
    settings = SimpleNamespace(
        pool_serving_contract_enabled=True,
        native_inline_replay_enabled=True,
        pool_protected_emails=["desktop@example.com"],
        pool_protected_principals=["desktop"],
        pool_fresh_work_cutoff_percent=98,
        pool_bound_work_cutoff_percent=99.5,
        pool_usage_max_age_seconds=180,
        pool_refresh_replay_fence_enabled=True,
        http_responses_session_bridge_enabled=False,
    )
    effective = SimpleNamespace(
        api_key_auth_enabled=True,
        upstream_stream_transport="http",
        http_downstream_transport_policy="always_http",
        routing_strategy="capacity_weighted",
        proxy_account_response_create_limit=4,
        proxy_account_stream_limit=8,
    )
    monkeypatch.setattr(pool_serving, "get_settings", lambda: settings)
    monkeypatch.setattr(
        pool_serving, "get_settings_cache", lambda: SimpleNamespace(get=AsyncMock(return_value=effective))
    )
    app = FastAPI()
    app.dependency_overrides[pool_serving.validate_dashboard_session] = lambda: None
    calls = []

    @app.post("/backend-api/codex/responses")
    async def response():
        calls.append(1)
        return {"ok": True}

    pool_serving.install_pool_serving_contract(app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        measured = (await client.get("/api/pool/metadata")).json()
        assert (await client.put("/api/settings", json={"routingStrategy": "round_robin"})).status_code == 409
        path = "/backend-api/codex/responses"
        assert (await client.post(path)).status_code == 409
        headers = {"x-codex-pool-identity": measured["identity"]}
        assert (await client.post(path, headers=headers)).status_code == 200
        effective.routing_strategy = "round_robin"
        assert (await client.post(path, headers=headers)).status_code == 409
        assert calls == [1]


def test_disabled_pool_contract_adds_no_routes_or_middleware(monkeypatch):
    monkeypatch.setattr(pool_serving, "get_settings", lambda: SimpleNamespace(pool_serving_contract_enabled=False))
    app = FastAPI()
    before = list(app.routes)
    pool_serving.install_pool_serving_contract(app)
    assert app.routes == before
    assert not app.user_middleware

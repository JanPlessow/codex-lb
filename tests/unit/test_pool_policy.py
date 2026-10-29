from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core import pool_policy
from app.core.crypto import TokenEncryptor
from app.modules.accounts.auth_manager import AuthManager
from app.modules.accounts.repository import AccountsRepository


@pytest.fixture
def policy(monkeypatch):
    settings = SimpleNamespace(
        pool_protected_emails=["desktop@example.com"],
        pool_protected_principals=["desktop-principal"],
        pool_fresh_work_cutoff_percent=98.0,
        pool_bound_work_cutoff_percent=99.5,
        pool_usage_max_age_seconds=180,
    )
    monkeypatch.setattr(pool_policy, "get_settings", lambda: settings)
    return settings


def token(principal="worker", email="worker@example.com"):
    claims = {
        "sub": principal,
        "email": email,
        "https://api.openai.com/auth": {"chatgpt_account_id": "shared-workspace"},
    }
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


def account(access=None, identity=None):
    encryptor = TokenEncryptor()
    return SimpleNamespace(
        email="worker@example.com",
        chatgpt_user_id="worker",
        access_token_encrypted=encryptor.encrypt(access or token()),
        id_token_encrypted=encryptor.encrypt(identity or token()),
    )


def usage(used=10, age=0, reset=300):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        used_percent=used, recorded_at=now - timedelta(seconds=age), reset_at=now.timestamp() + reset
    )


@pytest.mark.parametrize(
    "access,identity",
    [
        (token(email=" DESKTOP@example.com "), token()),
        (token(principal="desktop-principal"), token()),
        (token(), token(principal="desktop-principal")),
        ("malformed", token()),
    ],
)
def test_row_metadata_cannot_hide_protected_or_unidentified_credentials(policy, access, identity):
    with pytest.raises(pool_policy.ProtectedPoolIdentity):
        pool_policy.assert_pool_account(account(access, identity))


def test_same_workspace_is_not_same_principal(policy):
    pool_policy.assert_pool_account(account())
    pool_policy.assert_pool_account(account(token("another-worker"), token("another-worker")))


@pytest.mark.asyncio
@pytest.mark.parametrize("workspace", [None, "shared-workspace"])
async def test_import_preserves_three_seats_in_same_workspace(policy, db_setup, workspace):
    from app.db.session import SessionLocal
    from app.modules.accounts.service import AccountsService

    async with SessionLocal() as session:
        repository = AccountsRepository(session)
        service = AccountsService(repo=repository)
        saved = []
        for principal in ("worker-a", "worker-b", "worker-c"):
            claims = {
                "sub": principal,
                "email": principal + "@example.com",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "shared-workspace",
                    "workspace_id": workspace,
                },
            }
            body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
            credential = f"header.{body}.signature"
            result = await service.import_account(
                json.dumps(
                    {
                        "tokens": {
                            "access_token": credential,
                            "id_token": credential,
                            "refresh_token": "synthetic-refresh-" + principal,
                            "account_id": "shared-workspace",
                        }
                    }
                ).encode()
            )
            saved.append(result.account_id)
        assert len(set(saved)) == 3
        rows = await repository.list_accounts()
        assert {row.email for row in rows} == {"worker-a@example.com", "worker-b@example.com", "worker-c@example.com"}
        crypt = TokenEncryptor()
        assert {crypt.decrypt(row.refresh_token_encrypted) for row in rows} == {
            "synthetic-refresh-worker-a",
            "synthetic-refresh-worker-b",
            "synthetic-refresh-worker-c",
        }


@pytest.mark.asyncio
async def test_protected_refresh_rejected_before_network_or_claim_acquisition(policy):
    manager = AuthManager(AsyncMock())
    manager._run_refresh = AsyncMock()
    with pytest.raises(pool_policy.ProtectedPoolIdentity):
        await manager.ensure_fresh(account(token("desktop-principal")), force=True)
    manager._run_refresh.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["upsert", "upsert_account_slot", "replace_reauthorized"])
async def test_import_denial_precedes_database_write(policy, method):
    session = AsyncMock()
    repo = AccountsRepository(session)
    protected = account(token("desktop-principal"))
    args = ("existing", protected) if method == "replace_reauthorized" else (protected,)
    with pytest.raises(pool_policy.ProtectedPoolIdentity):
        await getattr(repo, method)(*args)
    session.commit.assert_not_awaited()
    session.execute.assert_not_awaited()


@pytest.mark.parametrize(
    "bad",
    [
        {"used": 98},
        {"used": 100},
        {"used": float("nan")},
        {"used": -1},
        {"age": 181},
        {"age": -10},
        {"reset": -1},
    ],
)
@pytest.mark.parametrize("window", ["primary", "secondary"])
def test_no_fresh_work_above_cutoff_or_without_current_evidence(policy, bad, window):
    bad = usage(**bad)
    primary, secondary = (bad, usage()) if window == "primary" else (usage(), bad)
    assert not pool_policy.quota_admits(primary, secondary, bound=False)


def test_exact_boundary_reserve_and_observed_reset(policy):
    assert pool_policy.quota_admits(usage(97.99), usage(), bound=False)
    assert not pool_policy.quota_admits(usage(98), usage(), bound=False)
    assert pool_policy.quota_admits(usage(99), usage(), bound=True)
    assert not pool_policy.quota_admits(usage(99.5), usage(), bound=True)
    assert not pool_policy.quota_admits(usage(98, reset=-1), usage(), bound=False)
    assert pool_policy.quota_admits(usage(0), usage(), bound=False)


@pytest.mark.asyncio
async def test_authoritative_selection_filters_cutoff_and_protected_then_recovers(policy):
    from app.modules.proxy.load_balancer import LoadBalancer
    from tests.unit.test_load_balancer_concurrency import (
        _make_account,
        _repo_factory,
        _StubAccountsRepository,
        _StubUsageRepository,
        _usage_row_with_percent,
    )

    crypt = TokenEncryptor()
    accounts = [_make_account("pool-policy-" + suffix) for suffix in "abc"]
    for item in accounts:
        item.access_token_encrypted = crypt.encrypt(token(item.id))
        item.id_token_encrypted = crypt.encrypt(token(item.id))
    # Healthy quota and innocent row metadata cannot hide the desktop token.
    accounts[0].access_token_encrypted = crypt.encrypt(token("desktop-principal"))
    reset = int(datetime.now(timezone.utc).timestamp()) + 300
    primary = {
        item.id: _usage_row_with_percent(i, item.id, used_percent=10, reset_at=reset) for i, item in enumerate(accounts)
    }
    secondary = {
        item.id: _usage_row_with_percent(i + 10, item.id, used_percent=10, reset_at=reset)
        for i, item in enumerate(accounts)
    }
    secondary[accounts[1].id].used_percent = 98
    repo = _StubUsageRepository(primary, secondary)
    balancer = LoadBalancer(lambda: _repo_factory(_StubAccountsRepository(accounts), repo))
    first = await balancer.select_account(lease_kind="stream")
    assert first.account is not None
    assert first.account.id == accounts[2].id
    await balancer.release_account_lease(first.lease)
    primary[accounts[2].id].used_percent = 98
    # No fallback to either above-cutoff account, even with no other capacity.
    exhausted = await balancer.select_account(lease_kind="stream")
    assert exhausted.account is None
    # An actual new observation restores eligibility on the same balancer.
    secondary[accounts[1].id].used_percent = 0
    recovered = await balancer.select_account(lease_kind="stream")
    assert recovered.account is not None
    assert recovered.account.id == accounts[1].id
    await balancer.release_account_lease(recovered.lease)


@pytest.mark.parametrize("has_primary,has_secondary", [(False, False), (True, False), (False, True)])
def test_pool_requires_at_least_one_current_window(policy, has_primary, has_secondary):
    primary = usage() if has_primary else None
    secondary = usage() if has_secondary else None
    assert pool_policy.quota_admits(primary, secondary, bound=False) is (primary is not None or secondary is not None)

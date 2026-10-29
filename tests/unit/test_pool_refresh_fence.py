from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.core import pool_refresh_fence as fence
from app.core.auth.refresh import RefreshError


@pytest.fixture
def enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(
        fence, "get_settings", lambda: SimpleNamespace(data_dir=tmp_path, pool_refresh_replay_fence_enabled=True)
    )
    return tmp_path


def test_crash_or_claim_expiry_does_not_authorize_same_token_again(enabled):
    fingerprint = "a" * 64
    fence.reserve_refresh_exchange(fingerprint)
    # A new claimant/process reads the same disk evidence. It does not depend
    # on an in-memory singleflight object or the expiring database claim.
    with pytest.raises(RefreshError) as caught:
        fence.reserve_refresh_exchange(fingerprint)
    assert caught.value.code == "refresh_outcome_uncertain"
    fence.reserve_refresh_exchange("b" * 64)  # genuinely rotated/repaired token


@pytest.mark.asyncio
async def test_ten_racing_claimants_only_one_gets_exchange_permission(enabled):
    def attempt():
        try:
            fence.reserve_refresh_exchange("c" * 64)
            return True
        except RefreshError:
            return False

    admitted = await asyncio.gather(*(asyncio.to_thread(attempt) for _ in range(10)))
    assert sum(admitted) == 1


def test_failed_durable_write_cannot_be_retried_as_an_unused_token(enabled, monkeypatch):
    original = fence.os.fsync
    monkeypatch.setattr(fence.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("disk failure")))
    with pytest.raises(RefreshError):
        fence.reserve_refresh_exchange("d" * 64)
    monkeypatch.setattr(fence.os, "fsync", original)
    with pytest.raises(RefreshError) as caught:
        fence.reserve_refresh_exchange("d" * 64)
    assert caught.value.code == "refresh_outcome_uncertain"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["response_lost", "persist_failed"])
async def test_auth_owner_restart_never_reexchanges_ambiguous_token(enabled, monkeypatch, fault):
    from unittest.mock import AsyncMock

    from app.core.auth.refresh import TokenRefreshResult
    from app.core.crypto import TokenEncryptor
    from app.core.utils.time import utcnow
    from app.db.models import Account, AccountStatus
    from app.modules.accounts import auth_manager
    from tests.unit.test_auth_manager import _DummyRepo

    exchange = AsyncMock(
        return_value=TokenRefreshResult(
            access_token="new-access",
            refresh_token="new-refresh",
            id_token="new-id",
            account_id="fenced-owner",
            plan_type=None,
            email=None,
        )
    )
    if fault == "response_lost":
        exchange.side_effect = RefreshError(
            "transport_error", "response lost after exchange", False, transport_error=True
        )
    monkeypatch.setattr(auth_manager, "refresh_access_token", exchange)
    crypt = TokenEncryptor()
    account = Account(
        id="fenced-owner",
        email="worker@example.com",
        plan_type="pro",
        access_token_encrypted=crypt.encrypt("old-access"),
        refresh_token_encrypted=crypt.encrypt("single-use-refresh"),
        id_token_encrypted=crypt.encrypt("old-id"),
        last_refresh=utcnow(),
        status=AccountStatus.ACTIVE,
        deactivation_reason=None,
    )
    repo = _DummyRepo()
    repo.accounts_by_id[account.id] = account
    if fault == "persist_failed":
        repo.rotate_tokens = AsyncMock(side_effect=OSError("storage unavailable after exchange"))
    with pytest.raises((RefreshError, OSError)):
        await auth_manager.AuthManager(repo).refresh_account(account)
    # Drop all process-local coordination, as on restart or an expired claim.
    auth_manager._clear_refresh_singleflight_state()
    with pytest.raises(RefreshError) as caught:
        await auth_manager.AuthManager(repo).refresh_account(account)
    assert caught.value.code == "refresh_outcome_uncertain"
    assert exchange.await_count == 1
    assert crypt.decrypt(account.refresh_token_encrypted) == "single-use-refresh"

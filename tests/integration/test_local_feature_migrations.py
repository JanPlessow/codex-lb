"""Published local and upstream schemas converge without losing user data."""

from __future__ import annotations

import pytest
from anyio import to_thread
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config.settings import get_settings
from app.db.migrate import check_schema_drift, inspect_migration_state, run_upgrade

MAIN = "20260918_000000_merge_scim_and_overflow_heads"
LOCAL = "20261020_000000_add_local_browser_personas"
HEAD = "20261029_000000_merge_local_feature_history"


@pytest.mark.asyncio
@pytest.mark.parametrize("start", ["base", MAIN, LOCAL])
async def test_published_histories_upgrade_preserving_rows(tmp_path, start):
    # CI's PostgreSQL lane supplies a dedicated test database; local runs get
    # one new SQLite file per history. No production database is consulted.
    configured = get_settings().database_url
    url = configured if configured.startswith("postgresql+") else f"sqlite+aiosqlite:///{tmp_path / 'upgrade.db'}"
    if configured.startswith("postgresql+"):
        engine = create_async_engine(url)
        async with engine.begin() as connection:
            await connection.execute(text("DROP SCHEMA public CASCADE"))
            await connection.execute(text("CREATE SCHEMA public"))
        await engine.dispose()
    await to_thread.run_sync(lambda: run_upgrade(url, start, bootstrap_legacy=False))
    engine = create_async_engine(url)
    try:
        if start != "base":
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO accounts (id, email, plan_type, codex_installation_id, access_token_encrypted, "
                        "refresh_token_encrypted, id_token_encrypted, last_refresh, status, routing_policy"
                        ") VALUES "
                        "('preserved', 'synthetic@example.com', 'pro', 'test-installation', "
                        ":access, :refresh, :id_token, "
                        "CURRENT_TIMESTAMP, 'active', 'normal')"
                    ),
                    {"access": b"synthetic-access", "refresh": b"synthetic-refresh", "id_token": b"synthetic-id"},
                )
                if start == LOCAL:
                    await connection.execute(
                        text(
                            "INSERT INTO browser_personas (id, account_id, state, route_mode, route_fingerprint, "
                            "relay_port, created_at) VALUES ('persona', 'preserved', 'active', 'direct', "
                            "'synthetic', 32000, CURRENT_TIMESTAMP)"
                        )
                    )
        await to_thread.run_sync(lambda: run_upgrade(url, bootstrap_legacy=False))
        state = await to_thread.run_sync(lambda: inspect_migration_state(url))
        assert state.current_revision == state.head_revision == HEAD
        assert await to_thread.run_sync(lambda: check_schema_drift(url)) == ()
        if start != "base":
            async with engine.connect() as connection:
                assert (
                    await connection.execute(
                        text("SELECT refresh_token_encrypted FROM accounts WHERE id = 'preserved'")
                    )
                ).scalar_one() == b"synthetic-refresh"
                if start == LOCAL:
                    assert (
                        await connection.execute(text("SELECT account_id FROM browser_personas WHERE id = 'persona'"))
                    ).scalar_one() == "preserved"
    finally:
        await engine.dispose()

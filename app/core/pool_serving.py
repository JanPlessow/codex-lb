"""Bind native requests to the proxy build and policy measured by a caller."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from fastapi import Depends
from starlette.responses import JSONResponse

from app.core.auth.dependencies import validate_dashboard_session
from app.core.config.settings import get_settings
from app.core.config.settings_cache import get_settings_cache


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def install_pool_serving_contract(app):
    settings = get_settings()
    if not settings.pool_serving_contract_enabled:
        return
    root = Path(__file__).resolve().parents[1]
    files = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*.py"))
    }
    for name in ("pyproject.toml", "uv.lock"):
        files[name] = hashlib.sha256((root.parent / name).read_bytes()).hexdigest()
    build = digest(files)
    policy_lock = asyncio.Lock()
    sealed = False
    static = {
        "inline_replay": settings.native_inline_replay_enabled,
        "protected_emails": sorted(settings.pool_protected_emails),
        "protected_principals": sorted(settings.pool_protected_principals),
        "fresh_cutoff": settings.pool_fresh_work_cutoff_percent,
        "bound_cutoff": settings.pool_bound_work_cutoff_percent,
        "usage_max_age": settings.pool_usage_max_age_seconds,
        "refresh_fence": settings.pool_refresh_replay_fence_enabled,
        "session_bridge": settings.http_responses_session_bridge_enabled,
    }

    async def metadata():
        effective = await get_settings_cache().get()
        policy = {
            name: getattr(effective, name)
            for name in (
                "api_key_auth_enabled",
                "upstream_stream_transport",
                "http_downstream_transport_policy",
                "routing_strategy",
                "proxy_account_response_create_limit",
                "proxy_account_stream_limit",
            )
        }
        identity = digest({"build": build, "static": static, "policy": policy})
        return {
            "contract_version": 1,
            "identity": identity,
            "build": build,
            "policy": policy,
            "static_policy_digest": digest(static),
        }

    @app.get("/api/pool/metadata", dependencies=[Depends(validate_dashboard_session)])
    async def pool_metadata():
        nonlocal sealed
        async with policy_lock:
            observed = await metadata()
            sealed = True
            return observed

    @app.middleware("http")
    async def enforce_serving_identity(request, call_next):
        path = request.url.path.rstrip("/")
        if path == "/api/settings" and request.method in ("PUT", "PATCH", "POST"):
            async with policy_lock:
                if sealed:
                    return JSONResponse(
                        status_code=409,
                        content={
                            "error": {
                                "code": "pool_policy_sealed",
                                "message": "Drain the pool and restart before changing measured serving policy.",
                            }
                        },
                    )
                return await call_next(request)
        if path.endswith("/responses") and (path.startswith("/backend-api/") or path.startswith("/v1/")):
            observed = await metadata()
            if request.headers.get("x-codex-pool-identity") != observed["identity"]:
                return JSONResponse(
                    status_code=409,
                    content={
                        "error": {
                            "code": "pool_serving_identity_changed",
                            "message": "Pool serving identity changed; revalidate before starting a new generation.",
                            "type": "invalid_request_error",
                        }
                    },
                )
        return await call_next(request)

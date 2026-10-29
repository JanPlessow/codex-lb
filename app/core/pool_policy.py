"""Local pool admission policy, independent of dashboard routing preferences."""

from __future__ import annotations

import base64
import json
import math
from datetime import datetime, timezone
from typing import Any

from app.core.config.settings import get_settings


class ProtectedPoolIdentity(ValueError):
    """No credential material is included in this error."""


def assert_pool_identity(email: str | None, principal: str | None) -> None:
    settings = get_settings()
    denied_emails = {value.strip().casefold() for value in settings.pool_protected_emails}
    if (email or "").strip().casefold() in denied_emails or (
        principal and principal in settings.pool_protected_principals
    ):
        raise ProtectedPoolIdentity("Protected desktop identity is not permitted in the automation pool")


def assert_pool_tokens(access_token: str, id_token: str) -> None:
    settings = get_settings()
    if not (settings.pool_protected_emails or settings.pool_protected_principals):
        return
    # Claims are a deny check, not signature authentication; upstream still
    # authenticates the actual token. Inspect both, so editable row metadata
    # cannot conceal a protected access token behind another user's ID token.
    for token in (access_token, id_token):
        try:
            encoded = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            auth = claims.get("https://api.openai.com/auth", {})
            profile = claims.get("https://api.openai.com/profile", {})
            if not isinstance(auth, dict) or not isinstance(profile, dict):
                raise ValueError
            principals = [claims.get("sub"), auth.get("chatgpt_user_id"), auth.get("user_id")]
            if not any(isinstance(value, str) and value for value in principals):
                raise ValueError
            for principal in principals:
                assert_pool_identity(claims.get("email") or profile.get("email"), principal)
        except ProtectedPoolIdentity:
            raise
        except (ValueError, TypeError, IndexError, AttributeError):
            raise ProtectedPoolIdentity("Cannot establish pool credential identity") from None


def assert_pool_account(account: Any) -> None:
    settings = get_settings()
    if not (settings.pool_protected_emails or settings.pool_protected_principals):
        return
    assert_pool_identity(account.email, account.chatgpt_user_id)
    from app.core.crypto import TokenEncryptor

    encryptor = TokenEncryptor()
    assert_pool_tokens(
        encryptor.decrypt(account.access_token_encrypted),
        encryptor.decrypt(account.id_token_encrypted),
    )


def pool_account_allowed(account: Any) -> bool:
    try:
        assert_pool_account(account)
    except (ProtectedPoolIdentity, ValueError):
        return False
    return True


def quota_admits(primary: Any, secondary: Any, *, bound: bool, now: datetime | None = None) -> bool:
    settings = get_settings()
    if settings.pool_fresh_work_cutoff_percent is None:
        return True
    now = now or datetime.now(timezone.utc)
    cutoff = settings.pool_bound_work_cutoff_percent if bound else settings.pool_fresh_work_cutoff_percent
    # Some plans expose only the weekly window. Validate every window that is
    # actually reported; an absent provider window is not evidence of zero
    # capacity and must not make the entire account unusable.
    # Weekly-only plans may persist a zero-duration secondary placeholder.
    # The authoritative weekly sample is carried in primary; the placeholder
    # has no quota window and must not make an otherwise eligible account fail
    # the freshness gate.
    windows = [
        usage for usage in (primary, secondary) if usage is not None and getattr(usage, "window_minutes", None) != 0
    ]
    if not windows:
        return False
    for usage in windows:
        if usage is None or not isinstance(usage.recorded_at, datetime):
            return False
        recorded = usage.recorded_at
        if recorded.tzinfo is None:
            recorded = recorded.replace(tzinfo=timezone.utc)
        age = (now - recorded).total_seconds()
        used = usage.used_percent
        if not isinstance(used, (int, float)) or not math.isfinite(used) or not 0 <= used < cutoff:
            return False
        if not 0 <= age <= settings.pool_usage_max_age_seconds:
            return False
        if usage.reset_at is not None and usage.reset_at <= now.timestamp():
            return False
    return True

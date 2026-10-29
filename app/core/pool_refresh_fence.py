"""Single-host durable no-reexchange fence for the local pool's rotating tokens.

The normal database claim remains the concurrency mechanism. This record covers
the separate crash window after upstream consumes a token but before persistence.
It intentionally never expires: a new credential has a different fingerprint.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from app.core.auth.refresh import RefreshError
from app.core.config.settings import get_settings


def reserve_refresh_exchange(fingerprint: str) -> None:
    settings = get_settings()
    if not settings.pool_refresh_replay_fence_enabled:
        return
    root = Path(settings.data_dir) / "pool-refresh-attempts"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise RefreshError("refresh_fence_unavailable", "Private refresh fence is unavailable", False)
    try:
        fd = os.open(root / fingerprint, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise RefreshError(
            "refresh_outcome_uncertain",
            "This credential already began a refresh exchange; recover the committed credential or reauthenticate",
            True,
        ) from None
    try:
        with os.fdopen(fd, "w") as stream:
            parent = os.open(root.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            json.dump({"state": "exchange_reserved", "at": time.time()}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        # Leave the reservation in place. No network call follows a failed
        # durable write, and the next process cannot assume it is unconsumed.
        raise RefreshError("refresh_fence_unavailable", "Refresh reservation could not be persisted", False) from None

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from sqlalchemy import select

from app.core.config.settings import get_settings
from app.db.models import BrowserPersona
from app.db.session import get_background_session
from app.modules.local_browser.repository import PersonaRoute, browser_error, load_persona_route
from app.modules.local_browser.transport import connect_target, open_target, relay

logger = logging.getLogger(__name__)
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


def capability_enabled() -> bool:
    settings = get_settings()
    return settings.local_browser_enabled and sys.platform == "darwin" and settings.database_url.startswith("sqlite")


def profile_root() -> Path:
    return get_settings().data_dir / "browser-personas"


@dataclass
class Listener:
    route: PersonaRoute
    server: asyncio.Server | None = None
    valid: bool = True
    tasks: set[asyncio.Task[None]] = field(default_factory=set)

    async def revoke(self) -> None:
        # Keep the listener bound to this persona. Old browser processes must
        # never find another persona on the same port.
        self.valid = False
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)


class BrowserRuntime:
    def __init__(self) -> None:
        self.listeners: dict[str, Listener] = {}
        self.lock = asyncio.Lock()
        self.flow_lock = asyncio.Lock()
        self.watcher: asyncio.Task[None] | None = None
        self.owner_file: IO[str] | None = None

    async def start(self) -> None:
        if not capability_enabled() or self.owner_file is not None:
            return
        import fcntl

        root = profile_root()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        owner = (root / "manager.lock").open("a+")
        try:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            owner.close()
            logger.warning("Local browser manager is already owned by another process")
            return
        self.owner_file = owner
        async with get_background_session() as session:
            ids = list((await session.scalars(select(BrowserPersona.id))).all())
        for persona_id in ids:
            try:
                await self.ensure(await load_persona_route(persona_id))
            except Exception:
                logger.info("Local browser persona remains unavailable until reopened")
        try:
            from app.db.models import BrowserOAuthFlow, OAuthFlowState
            from app.modules.accounts.repository import AccountsRepository
            from app.modules.oauth.service import OauthService

            async with get_background_session() as session:
                flow_ids = list(
                    (
                        await session.scalars(
                            select(BrowserOAuthFlow.flow_id)
                            .join(OAuthFlowState, OAuthFlowState.flow_id == BrowserOAuthFlow.flow_id)
                            .where(OAuthFlowState.status == "pending")
                        )
                    ).all()
                )
                if flow_ids:
                    oauth_svc = OauthService(AccountsRepository(session))
                    for fid in flow_ids:
                        try:
                            await oauth_svc.resume_browser_callback(fid)
                        except Exception:
                            pass
        except Exception:
            pass
        self.watcher = asyncio.create_task(self._watch(), name="local-browser-routes")

    async def ensure(self, route: PersonaRoute) -> None:
        if self.owner_file is None:
            raise browser_error("The local browser manager is unavailable.")
        async with self.lock:
            current = self.listeners.get(route.persona_id)
            if current is not None:
                if current.route.port != route.port:
                    raise browser_error("Browser listener ownership changed unexpectedly.")
                if not current.valid or current.route.fingerprint != route.fingerprint:
                    await current.revoke()
                    current.route = route
                    current.valid = True
                return
            listener = Listener(route)
            listener.server = await asyncio.start_server(
                lambda r, w: self._accept(listener, r, w), "127.0.0.1", route.port, limit=65536
            )
            self.listeners[route.persona_id] = listener

    def _accept(self, listener: Listener, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(listener.tasks) >= 512:
            writer.close()
            return
        task = asyncio.create_task(self._connect(listener, reader, writer))
        listener.tasks.add(task)
        task.add_done_callback(listener.tasks.discard)

    async def _connect(self, listener: Listener, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        accepted = False
        try:
            async with asyncio.timeout(20):
                request = await reader.readuntil(b"\r\n\r\n")
                if len(request) > 8192:
                    raise ValueError("Headers too large")
                host = connect_target(request.split(b"\r\n", 1)[0].decode("ascii"))
                current = await load_persona_route(listener.route.persona_id)
                if not listener.valid or current.fingerprint != listener.route.fingerprint:
                    raise browser_error("The account browser route changed. Reopen it from the dashboard.")
                upstream_reader, upstream_writer = await open_target(host, current.route)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                accepted = True
            await relay(reader, writer, upstream_reader, upstream_writer)
        except asyncio.CancelledError:
            raise
        except Exception:
            if not accepted:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        finally:
            for stream in (upstream_writer, writer):
                if stream is not None:
                    stream.close()
                    try:
                        await asyncio.wait_for(stream.wait_closed(), timeout=2)
                    except (OSError, TimeoutError):
                        pass

    async def revalidate(self) -> None:
        for listener in tuple(self.listeners.values()):
            try:
                route = await load_persona_route(listener.route.persona_id)
                if route.fingerprint != listener.route.fingerprint:
                    await listener.revoke()
            except Exception:
                await listener.revoke()

    async def _watch(self) -> None:
        while True:
            await asyncio.sleep(1)
            await self.revalidate()

    async def stop(self) -> None:
        if self.watcher:
            self.watcher.cancel()
            await asyncio.gather(self.watcher, return_exceptions=True)
            self.watcher = None
        for listener in self.listeners.values():
            await listener.revoke()
            if listener.server:
                listener.server.close()
                await listener.server.wait_closed()
        self.listeners.clear()
        if self.owner_file:
            self.owner_file.close()
            self.owner_file = None

    async def launch(self, persona_id: str, url: str) -> None:
        route = await load_persona_route(persona_id)
        await self.ensure(route)
        try:
            async with asyncio.timeout(15):
                _, upstream = await open_target("auth.openai.com", route.route)
                upstream.close()
                await upstream.wait_closed()
        except Exception:
            raise browser_error(
                "The assigned connection cannot reach sign-in. "
                "Check the proxy and retry; no alternate connection was used."
            ) from None
        path = profile_root() / persona_id
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or path.resolve().parent != profile_root().resolve():
            raise browser_error("Invalid managed profile location.")
        proxy = f"http://127.0.0.1:{route.port}"
        # Chrome reuses a running process for the same data directory and
        # ignores replacement network switches. Verify before sending its URL.
        probe = await asyncio.create_subprocess_exec("/bin/ps", "-axo", "command=", stdout=asyncio.subprocess.PIPE)
        try:
            stdout, _ = await asyncio.wait_for(probe.communicate(), timeout=5)
        except BaseException:
            if probe.returncode is None:
                probe.kill()
            await probe.wait()
            raise
        for line in stdout.decode(errors="replace").splitlines():
            if str(CHROME) in line and f"--user-data-dir={path}" in line:
                if f"--proxy-server={proxy}" not in line:
                    raise browser_error("Close this account's old Chrome window, then reopen it from Codex LB.")
        if not CHROME.is_file():
            raise browser_error("Google Chrome is not installed in Applications.")
        process = await asyncio.create_subprocess_exec(
            "/usr/bin/open",
            "-n",
            "-a",
            str(CHROME.parents[2]),
            "--args",
            f"--user-data-dir={path}",
            f"--proxy-server={proxy}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            url,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            result = await asyncio.wait_for(process.wait(), timeout=10)
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        if result:
            raise browser_error("Chrome could not be opened. Retry from this account.")


_runtime = BrowserRuntime()


def get_browser_runtime() -> BrowserRuntime:
    return _runtime

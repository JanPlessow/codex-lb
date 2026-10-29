from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from app.core.upstream_proxy.types import ResolvedProxyEndpoint, ResolvedUpstreamRoute
from app.modules.local_browser import runtime as runtime_module
from app.modules.local_browser.repository import PersonaRoute, browser_error
from app.modules.local_browser.runtime import BrowserRuntime
from app.modules.local_browser.transport import connect_target, open_target


@pytest.mark.parametrize(
    "line",
    [
        "GET https://example.com/ HTTP/1.1",
        "CONNECT localhost:443 HTTP/1.1",
        "CONNECT 127.0.0.1:443 HTTP/1.1",
        "CONNECT example.com:80 HTTP/1.1",
        "CONNECT example.com:443 HTTP/1.1 extra",
        "CONNECT a.local:443 HTTP/1.1",
    ],
)
def test_connect_rejects_unsupported_or_private_destinations(line):
    with pytest.raises(ValueError):
        connect_target(line)


@pytest.mark.asyncio
async def test_authenticated_socks_tunnel_uses_remote_dns_and_transmits_bytes():
    observed = []

    async def proxy(reader, writer):
        try:
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            assert version == 5 and 2 in methods
            writer.write(b"\x05\x02")
            await writer.drain()
            auth_version, user_length = await reader.readexactly(2)
            username = await reader.readexactly(user_length)
            password_length = (await reader.readexactly(1))[0]
            password = await reader.readexactly(password_length)
            observed.append((auth_version, username, password))
            writer.write(b"\x01\x00")
            await writer.drain()
            head = await reader.readexactly(4)
            assert head == b"\x05\x01\x00\x03"
            length = (await reader.readexactly(1))[0]
            host = await reader.readexactly(length)
            port = int.from_bytes(await reader.readexactly(2), "big")
            observed.append((host, port))
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            data = await reader.readexactly(4)
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(proxy, "127.0.0.1", 0)
    endpoint = ResolvedProxyEndpoint(
        "ep", "socks5h", "127.0.0.1", server.sockets[0].getsockname()[1], "test-user", "test-password"
    )
    try:
        reader, writer = await open_target("example.com", ResolvedUpstreamRoute("account_bound", "pool", endpoint))
        writer.write(b"ping")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(4), 2) == b"ping"
        writer.close()
        await writer.wait_closed()
        assert observed == [(1, b"test-user", b"test-password"), (b"example.com", 443)]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_failed_http_proxy_never_connects_directly(monkeypatch):
    attempted = []

    async def refused(host, port, **kwargs):
        attempted.append((host, port))
        raise ConnectionRefusedError("synthetic failure")

    monkeypatch.setattr(asyncio, "open_connection", refused)
    endpoint = ResolvedProxyEndpoint("ep", "http", "proxy.example", 3128, "user", "password")
    with pytest.raises(ConnectionRefusedError):
        await open_target("destination.example", ResolvedUpstreamRoute("account_bound", "pool", endpoint))
    assert attempted == [("proxy.example", 3128)]


@pytest.mark.asyncio
async def test_live_tunnel_is_revoked_and_port_retains_persona_ownership(monkeypatch, tmp_path, unused_tcp_port):
    upstream_connections = []

    async def echo(reader, writer):
        upstream_connections.append(writer)
        try:
            while data := await reader.read(1024):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)

    async def connect(_host, _route):
        return await asyncio.open_connection("127.0.0.1", echo_server.sockets[0].getsockname()[1])

    state = PersonaRoute("persona-a", unused_tcp_port, "revision-a", None)
    lookup = AsyncMock(return_value=state)
    monkeypatch.setattr(runtime_module, "load_persona_route", lookup)
    monkeypatch.setattr(runtime_module, "open_target", connect)
    runtime = BrowserRuntime()
    runtime.owner_file = (tmp_path / "lock").open("w")
    try:
        await runtime.ensure(state)
        reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        assert b"200" in await reader.readuntil(b"\r\n\r\n")
        writer.write(b"ping")
        await writer.drain()
        assert await reader.readexactly(4) == b"ping"
        lookup.side_effect = browser_error("route removed")
        await runtime.revalidate()
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await writer.wait_closed()
        assert runtime.listeners["persona-a"].server.is_serving()
        reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        assert b"502" in await reader.read()
        assert len(upstream_connections) == 1
        writer.close()
        await writer.wait_closed()
    finally:
        await runtime.stop()
        echo_server.close()
        await echo_server.wait_closed()

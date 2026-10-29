"""Bounded HTTPS CONNECT adapter. It never decrypts destination TLS."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
import socket
import ssl

from python_socks import ProxyType
from python_socks.async_.asyncio import Proxy

from app.core.upstream_proxy.types import ResolvedUpstreamRoute


def connect_target(request_line: str) -> str:
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise ValueError("Only HTTPS CONNECT is supported")
    host, separator, port = parts[1].rpartition(":")
    if separator != ":" or port != "443" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise ValueError("Invalid HTTPS target")
    host = host.lower().rstrip(".")
    if "." not in host or host.endswith((".localhost", ".local")):
        raise ValueError("Local targets are not supported")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("Private targets are not supported")
    return host


async def open_target(
    host: str, route: ResolvedUpstreamRoute | None
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if route is None:
        # Validate the addresses actually used, rather than resolving twice.
        addresses = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        for family, _, _, _, address in addresses:
            if not ipaddress.ip_address(address[0]).is_global:
                raise ValueError("Private targets are not supported")
        last_error: OSError | None = None
        for family, _, _, _, address in addresses:
            try:
                return await asyncio.open_connection(str(address[0]), 443, family=family)
            except OSError as exc:
                last_error = exc
        raise last_error or OSError("Target has no public address")
    if route.fallbacks:
        raise ValueError("Browser routes cannot contain fallback endpoints")
    endpoint = route.endpoint
    if endpoint.scheme in {"socks5", "socks5h"}:
        use_rdns = endpoint.scheme == "socks5h"
        targets = [host]
        if not use_rdns:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
                )
                ipv4_targets = []
                for _, _, _, _, sockaddr in infos:
                    ip_str = str(sockaddr[0])
                    if ipaddress.ip_address(ip_str).is_global and ip_str not in ipv4_targets:
                        ipv4_targets.append(ip_str)
                if ipv4_targets:
                    targets = ipv4_targets[:2]
            except OSError:
                pass
        last_exc: BaseException | None = None
        for target in targets:
            proxy = Proxy(
                ProxyType.SOCKS5,
                endpoint.host,
                endpoint.port,
                username=endpoint.username,
                password=endpoint.password,
                rdns=use_rdns,
            )
            try:
                sock = await proxy.connect(target, 443, timeout=15)
            except BaseException as exc:
                last_exc = exc
                continue
            try:
                return await asyncio.open_connection(sock=sock, limit=65536)
            except BaseException:
                sock.close()
                raise
        assert last_exc is not None
        raise last_exc
    if endpoint.scheme not in {"http", "https"}:
        raise ValueError("Unsupported browser proxy protocol")
    reader, writer = await asyncio.open_connection(
        endpoint.host,
        endpoint.port,
        ssl=ssl.create_default_context() if endpoint.scheme == "https" else None,
        limit=8192,
    )
    try:
        headers = [f"CONNECT {host}:443 HTTP/1.1", f"Host: {host}:443"]
        if endpoint.username:
            auth = base64.b64encode(f"{endpoint.username}:{endpoint.password or ''}".encode()).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {auth}")
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        reply = await reader.readuntil(b"\r\n\r\n")
        if len(reply) > 8192 or reply.split(b"\r\n", 1)[0].split(b" ")[1:2] != [b"200"]:
            raise OSError("The assigned proxy refused the tunnel")
        return reader, writer
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise


async def copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        data = await asyncio.wait_for(reader.read(65536), timeout=300)
        if not data:
            return
        writer.write(data)
        await writer.drain()


async def relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    tasks = [
        asyncio.create_task(copy_stream(client_reader, upstream_writer)),
        asyncio.create_task(copy_stream(upstream_reader, client_writer)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=3600)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

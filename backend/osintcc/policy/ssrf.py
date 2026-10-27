"""SSRF defence (spec 3 trust boundary 6): block private/loopback/link-local/metadata/reserved destinations.

Validation happens on every hop (redirects) and the connection is pinned to the validated IP so DNS rebinding
between check and connect cannot succeed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import httpx

Resolver = Callable[[str], Awaitable[list[str]]]
MAX_BODY = 8 * 1024 * 1024
MAX_REDIRECTS = 4
METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


class DestinationDenied(Exception):
    pass


def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if str(addr) in METADATA_IPS:
        return False
    return addr.is_global and not (addr.is_multicast or addr.is_reserved or addr.is_loopback
                                   or addr.is_link_local or addr.is_private or addr.is_unspecified)


async def system_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(i[4][0]) for i in infos})


async def validate_host(host: str, resolver: Resolver = system_resolver, allow_private: bool = False) -> list[str]:
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            ips = await resolver(host)
        except OSError as exc:
            raise DestinationDenied(f"cannot resolve {host}") from exc
    if not ips:
        raise DestinationDenied(f"no addresses for {host}")
    if not allow_private:
        bad = [ip for ip in ips if not ip_is_public(ip)]
        if bad:
            raise DestinationDenied(f"destination {host} resolves to non-public address {bad[0]}")
    return ips


class HttpResult:
    def __init__(self, status: int, headers: dict[str, str], body: bytes, url: str):
        self.status, self.headers, self.body, self.url = status, headers, body, url


class HttpClient(Protocol):
    """What an adapter needs from its HTTP client. SafeHttp implements it; the provider dispatcher wraps it without changing the contract."""

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResult: ...


class SafeHttp:
    """Minimal SSRF-safe GET client. `transport` is a test seam (httpx.MockTransport); host validation still runs."""

    def __init__(self, *, resolver: Resolver = system_resolver, allow_private: bool = False,
                 transport: httpx.AsyncBaseTransport | None = None, user_agent: str = "osintcc/0.1 (local research)",
                 timeout: float = 20.0):
        self.resolver, self.allow_private, self.transport = resolver, allow_private, transport
        self.user_agent, self.timeout = user_agent, timeout

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResult:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise DestinationDenied("only http(s) URLs with a host are allowed")
            ips = await validate_host(parts.hostname, self.resolver, self.allow_private)
            hdrs = {"User-Agent": self.user_agent, "Accept": "application/json, text/plain, */*", **(headers or {})}
            ext: dict = {}
            request_url = current
            if self.transport is None:
                # Pin to validated IP; keep Host header / SNI for the original hostname.
                ip = ips[0]
                netloc_ip = f"[{ip}]" if ":" in ip else ip
                port = f":{parts.port}" if parts.port else ""
                request_url = parts._replace(netloc=f"{netloc_ip}{port}").geturl()
                hdrs["Host"] = parts.netloc
                ext["sni_hostname"] = parts.hostname
            async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout, follow_redirects=False,
                                         verify=True if self.transport is None else False) as client:
                async with client.stream("GET", request_url, headers=hdrs, extensions=ext) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                        current = urljoin(current, resp.headers["location"])
                        continue
                    chunks, size = [], 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_BODY:
                            raise DestinationDenied("response exceeds size limit")
                        chunks.append(chunk)
                    return HttpResult(resp.status_code, {k.lower(): v for k, v in resp.headers.items()},
                                      b"".join(chunks), current)
        raise DestinationDenied("too many redirects")

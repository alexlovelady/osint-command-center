"""A controlled local lab for AIV tests: real TCP/TLS servers on 127.0.0.1 that record exactly what reached them, plus a scripted resolver.

The servers speak just enough HTTP/1.1 for header checks. Certificates are generated per test with `cryptography` (a throwaway CA), so TLS observations come from
real handshakes, not mocks. Nothing here leaves the machine.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(tmp: Path) -> tuple[Any, Any, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(_name("AIV test CA")).issuer_name(_name("AIV test CA")).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True).sign(key, hashes.SHA256()))
    pem = tmp / "ca.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, pem


def make_server_cert(tmp: Path, ca_key: Any, ca_cert: Any, names: list[str], *, days_valid: int = 120, expired: bool = False, self_signed: bool = False, rsa_bits: int | None = None,
                     tag: str = "srv") -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits) if rsa_bits else ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    nb, na = (now - dt.timedelta(days=60), now - dt.timedelta(days=5)) if expired else (now - dt.timedelta(days=1), now + dt.timedelta(days=days_valid))
    issuer = _name(names[0]) if self_signed else ca_cert.subject
    signer = key if self_signed else ca_key
    cert = (x509.CertificateBuilder().subject_name(_name(names[0])).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na).add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key() if self_signed else ca_key.public_key()), critical=False).sign(signer, hashes.SHA256()))
    cp, kp = tmp / f"{tag}.crt", tmp / f"{tag}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp


@dataclass
class Seen:
    method: str
    target: str
    headers: dict[str, str]


@dataclass
class Lab:
    """One server. `routes` maps a path to (status, headers, body) or a callable(seen) -> that tuple."""
    host: str = "127.0.0.1"
    port: int = 0
    routes: dict[str, Any] = field(default_factory=dict)
    seen: list[Seen] = field(default_factory=list)
    connections: int = 0
    delay: float = 0.0
    _server: asyncio.AbstractServer | None = None

    async def start(self, ssl_ctx: ssl.SSLContext | None = None) -> Lab:
        self._server = await asyncio.start_server(self._handle, self.host, 0, ssl=ssl_ctx)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ConnectionError, OSError):
            writer.close()
            return
        lines = raw.decode("latin-1").split("\r\n")
        method, target, _ = (lines[0].split(" ") + ["", "", ""])[:3]
        headers = {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines[1:] if ln)}
        seen = Seen(method, target, headers)
        self.seen.append(seen)
        if self.delay:
            await asyncio.sleep(self.delay)
        route = self.routes.get(target.split("?")[0], self.routes.get("*", (404, {}, b"not found")))
        status, hdrs, body = route(seen) if callable(route) else route
        reason = {200: "OK", 301: "Moved", 302: "Found", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "X")
        out = f"HTTP/1.1 {status} {reason}\r\n"
        h = {"Content-Length": str(len(body)), "Connection": "close", **hdrs}
        for k, v in h.items():
            for item in (v if isinstance(v, list) else [v]):
                out += f"{k}: {item}\r\n"
        writer.write(out.encode("latin-1") + b"\r\n" + (b"" if method == "HEAD" else body))
        try:
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError, ssl.SSLError):
            pass


class Resolver:
    """Scripted name resolution; counts calls so tests can prove a preview did none."""

    def __init__(self, table: dict[str, list[str]]):
        self.table, self.calls = dict(table), []

    async def __call__(self, host: str) -> list[str]:
        self.calls.append(host)
        if host not in self.table:
            raise OSError(f"no such host {host}")
        return list(self.table[host])


def server_ctx(cert: Path, key: Path, *, min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_version
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def client_trust(ca_pem: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(str(ca_pem))
    return ctx


GOOD_HEADERS = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains", "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "geolocation=()", "Content-Type": "text/html"}
WEAK_HEADERS = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3", "Content-Type": "text/html",
                "Set-Cookie": ["sid=SECRET-SESSION-VALUE; Path=/", "pref=dark; Path=/; Secure; HttpOnly; SameSite=Lax"]}

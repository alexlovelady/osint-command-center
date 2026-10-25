"""TLS posture check: handshakes only. Built in (Python `ssl`), so it works the same on Windows and Linux; sslscan is not used.

Per protocol version it attempts one handshake and records supported / not_supported / not_testable (the LOCAL TLS library may refuse legacy protocols; that is
reported as 'not testable', never as 'not supported'). It sends no application data and reads none. At most six handshakes per run.
"""
from __future__ import annotations

import asyncio
import hashlib
import ssl
import warnings
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from ...aiv import policy
from ...aiv.policy import Budget, BudgetExceeded
from ...policy.ssrf import system_resolver
from .http_metadata import _is_ip

Resolver = Callable[[str], Awaitable[list[str]]]
_VERSIONS = (("TLSv1.3", ssl.TLSVersion.TLSv1_3), ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.1", ssl.TLSVersion.TLSv1_1), ("TLSv1.0", ssl.TLSVersion.TLSv1))
HANDSHAKE_TIMEOUT = 6.0


def describe_certificate(der: bytes, host: str) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        ktype, bits = "RSA", pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        ktype, bits = "EC", pk.key_size
    elif isinstance(pk, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        ktype, bits = type(pk).__name__.replace("PublicKey", ""), 256
    elif isinstance(pk, dsa.DSAPublicKey):
        ktype, bits = "DSA", pk.key_size
    else:
        ktype, bits = "unknown", 0
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    sig = cert.signature_hash_algorithm
    sig_name = sig.name if isinstance(sig, hashes.HashAlgorithm) else "none"
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {"subject": cert.subject.rfc4514_string()[:300], "issuer": cert.issuer.rfc4514_string()[:300], "self_signed": cert.subject == cert.issuer, "san": list(sans)[:50],
            "not_before": nb.isoformat(), "not_after": na.isoformat(), "key_type": ktype, "key_bits": bits, "signature_hash": sig_name,
            "serial": format(cert.serial_number, "x")[:40], "sha256_fingerprint": hashlib.sha256(der).hexdigest(), "host_matches": _host_matches(host, sans)}


def _host_matches(host: str, sans: list[str]) -> bool:
    h = host.lower()
    for s in sans:
        s = s.lower()
        if s == h or (s.startswith("*.") and "." in h and h.split(".", 1)[1] == s[2:] and h.count(".") == s.count(".")):
            return True
    return False


async def probe_tls(auth: Any, host: str, port: int, budget: Budget, *, resolver: Resolver = system_resolver, trust_context: ssl.SSLContext | None = None,
                    now: Callable[[], datetime] = lambda: datetime.now(UTC), emit: Callable[[str, dict[str, Any]], None] | None = None) -> dict[str, Any]:
    emit = emit or (lambda k, p: None)
    out: dict[str, Any] = {"host": host, "port": port, "protocols": {}, "blocked": None, "certificate": None, "trust": None, "hostname_match": None, "negotiated": None, "cipher": None}
    gate = policy.check_host_port(auth, "tls_handshake", host, port, now())
    if not gate:
        out["blocked"] = {"code": gate.code, "reason": gate.reason}
        emit("blocked", out["blocked"])
        return out
    try:
        ips = [host] if _is_ip(host) else await resolver(host)
    except OSError:
        ips = []
    rd = policy.check_resolved(auth, host, ips)
    if not rd:
        out["blocked"] = {"code": rd.code, "reason": rd.reason}
        emit("blocked", out["blocked"])
        return out
    ip = ips[0]
    sni = None if _is_ip(host) else host
    der: bytes | None = None
    for name, ver in _VERSIONS:
        try:
            wait = budget.charge("tls_handshake", host)
        except BudgetExceeded as exc:
            out["blocked"] = {"code": "budget_exceeded", "reason": f"the {exc.what} budget is used up"}
            return out
        if wait:
            await asyncio.sleep(wait)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)            # TLS 1.0/1.1 are deprecated in Python on purpose: we only TEST for them
                ctx.minimum_version = ctx.maximum_version = ver
            ctx.set_ciphers("ALL:@SECLEVEL=0") if ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1) else None
        except (ValueError, ssl.SSLError):
            out["protocols"][name] = "not_testable"
            out["not_testable_reason"] = "the local TLS library does not allow this protocol version"
            continue
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni), HANDSHAKE_TIMEOUT)
        except (ssl.SSLError, ConnectionResetError) as exc:
            text = str(exc).upper()
            if "NO_PROTOCOLS_AVAILABLE" in text or "UNSUPPORTED_PROTOCOL" in text and "TLSV1_ALERT" not in text:
                out["protocols"][name] = "not_testable"
                out["not_testable_reason"] = "the local TLS library does not allow this protocol version"
            else:
                out["protocols"][name] = "not_supported"
            continue
        except (TimeoutError, OSError):
            out["protocols"][name] = "unreachable"
            continue
        sslobj = writer.get_extra_info("ssl_object")
        out["protocols"][name] = "supported"
        if out["negotiated"] is None and sslobj is not None:
            out["negotiated"] = sslobj.version()
            out["cipher"] = (sslobj.cipher() or ("",))[0]
            der = sslobj.getpeercert(binary_form=True)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        emit("handshake", {"protocol": name, "result": "supported"})
    if der:
        out["certificate"] = describe_certificate(der, host)
        out["hostname_match"] = out["certificate"]["host_matches"]
        # one more handshake with real verification, to say whether THIS machine would trust the connection
        try:
            budget.charge("tls_handshake", host)
            vctx = trust_context or ssl.create_default_context()
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=vctx, server_hostname=sni or host), HANDSHAKE_TIMEOUT)
            out["trust"] = "ok"
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError, ssl.SSLError):
                pass
        except ssl.SSLCertVerificationError as exc:
            out["trust"] = (exc.verify_message or str(exc))[:160]
        except (ssl.SSLError, TimeoutError, OSError, BudgetExceeded) as exc:
            out["trust"] = f"could not verify ({type(exc).__name__})"
    return out

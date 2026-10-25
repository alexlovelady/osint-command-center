"""Typed observation builders: security-header analysis, TLS certificate and protocol analysis, port results.

Each observation says what was OBSERVED (a measured value) and what is only INFERRED (a recommendation or a likely consequence). Severity is a hygiene rating of the
observed configuration, not a claim that anything is exploitable.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class Obs:
    check_type: str
    rule: str
    title: str
    severity: str = "info"                     # info | low | medium | high
    observed: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    basis: str = "observed"                    # observed | inferred
    confidence: str = "high"

    def key(self, asset: str) -> str:
        return hashlib.sha256(f"{self.check_type}|{asset}|{self.rule}".encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---- HTTP security headers ---------------------------------------------------------------------------------------------------------------
_VERSIONED = re.compile(r"\d+\.\d+")


def analyze_headers(headers: dict[str, str], *, scheme: str, status: int, set_cookies: list[str] | None = None) -> list[Obs]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[Obs] = []
    t = "http_security_header"
    if scheme == "http" and 200 <= status < 300:
        out.append(Obs("http_transport", "plain_http", "Content is served over plain HTTP", "medium", {"scheme": "http", "status": status},
                       "Serve the site over HTTPS and redirect HTTP to HTTPS."))
    if scheme == "https":
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(Obs(t, "hsts_missing", "Strict-Transport-Security is not set", "low", {"header": None},
                           "Send Strict-Transport-Security with a max-age of at least 15552000 seconds once HTTPS works everywhere."))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                out.append(Obs(t, "hsts_short", "Strict-Transport-Security max-age is short", "low", {"header": hsts, "max_age": age}, "Raise max-age to at least 15552000 (180 days)."))
            else:
                out.append(Obs(t, "hsts_ok", "Strict-Transport-Security is set", "info", {"header": hsts, "max_age": age}))
    csp = h.get("content-security-policy")
    if not csp:
        out.append(Obs(t, "csp_missing", "Content-Security-Policy is not set", "low", {"header": None}, "Define a Content-Security-Policy that restricts script and frame sources."))
    elif re.search(r"unsafe-(inline|eval)", csp):
        out.append(Obs(t, "csp_unsafe", "Content-Security-Policy allows unsafe-inline or unsafe-eval", "low", {"header": csp[:300]}, "Remove unsafe-inline/unsafe-eval; use nonces or hashes."))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Obs(t, "nosniff_missing", "X-Content-Type-Options: nosniff is not set", "low", {"header": h.get("x-content-type-options")}, "Send X-Content-Type-Options: nosniff."))
    if not h.get("x-frame-options") and "frame-ancestors" not in (csp or ""):
        out.append(Obs(t, "framing_unprotected", "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)", "low", {"x-frame-options": None},
                       "Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive."))
    if not h.get("referrer-policy"):
        out.append(Obs(t, "referrer_missing", "Referrer-Policy is not set", "info", {"header": None}, "Send Referrer-Policy: strict-origin-when-cross-origin or stricter."))
    if not h.get("permissions-policy"):
        out.append(Obs(t, "permissions_missing", "Permissions-Policy is not set", "info", {"header": None}, "Send a Permissions-Policy that disables features the site does not use."))
    server = h.get("server", "")
    if server and _VERSIONED.search(server):
        out.append(Obs(t, "server_version", "Server header discloses a software version", "low", {"server": server}, "Remove or genericise the version in the Server header."))
    if h.get("x-powered-by"):
        out.append(Obs(t, "powered_by", "X-Powered-By discloses the application platform", "low", {"x-powered-by": h["x-powered-by"]}, "Remove the X-Powered-By header."))
    acao, acac = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(Obs(t, "cors_wildcard_credentials", "CORS allows any origin together with credentials", "medium", {"access-control-allow-origin": acao, "allow-credentials": acac},
                       "Do not combine a wildcard origin with credentials; list trusted origins."))
    elif acao == "*":
        out.append(Obs(t, "cors_wildcard", "CORS allows any origin", "info", {"access-control-allow-origin": acao}, "Confirm the resource is meant to be public; otherwise restrict origins."))
    for i, c in enumerate(set_cookies or []):
        name = c.split("=", 1)[0].strip()[:60]
        flags = c.lower()
        missing = [f for f, present in (("Secure", "secure" in flags or scheme != "https"), ("HttpOnly", "httponly" in flags), ("SameSite", "samesite" in flags)) if not present]
        if missing:
            out.append(Obs("http_cookie", f"cookie_flags:{name}", f"Cookie '{name}' lacks {', '.join(missing)}", "low", {"cookie": name, "missing": missing},
                           "Set Secure, HttpOnly and SameSite on cookies that carry state. (Only the header was read; whether this cookie matters is not known.)", "inferred", "medium"))
    return out


# ---- TLS ---------------------------------------------------------------------------------------------------------------------------------
PROTOCOLS = ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0")


def analyze_tls(probe: dict[str, Any], now: datetime | None = None) -> list[Obs]:
    now = now or datetime.now(UTC)
    out: list[Obs] = []
    t = "tls_posture"
    protos = probe.get("protocols", {})
    for p in ("TLSv1.0", "TLSv1.1"):
        if protos.get(p) == "supported":
            out.append(Obs(t, f"legacy_{p}", f"{p} is accepted", "medium", {"protocol": p}, f"Disable {p}; require TLS 1.2 or newer."))
    if protos.get("TLSv1.3") == "not_supported" and protos.get("TLSv1.2") == "supported":
        out.append(Obs(t, "no_tls13", "TLS 1.3 is not offered", "info", {"protocol": "TLSv1.3"}, "Enable TLS 1.3 where the server software supports it."))
    if protos and not any(protos.get(p) == "supported" for p in ("TLSv1.3", "TLSv1.2")) and any(v == "not_supported" for v in protos.values()):
        out.append(Obs(t, "no_modern_tls", "Neither TLS 1.2 nor TLS 1.3 completed a handshake", "high", {"protocols": protos}, "Enable TLS 1.2 and TLS 1.3."))
    for p, v in protos.items():
        if v == "not_testable":
            out.append(Obs(t, f"not_testable_{p}", f"{p} could not be tested from this machine", "info", {"protocol": p, "reason": probe.get("not_testable_reason", "the local TLS library refuses this protocol")},
                           "", "inferred", "low"))
    c = probe.get("certificate")
    if c:
        nb, na = datetime.fromisoformat(c["not_before"]), datetime.fromisoformat(c["not_after"])
        days = (na - now).days
        if na <= now:
            out.append(Obs(t, "cert_expired", "The certificate has expired", "high", {"not_after": c["not_after"]}, "Renew the certificate."))
        elif days < 30:
            out.append(Obs(t, "cert_expiring", f"The certificate expires in {days} days", "medium", {"not_after": c["not_after"], "days": days}, "Renew the certificate before it expires."))
        if nb > now:
            out.append(Obs(t, "cert_not_yet_valid", "The certificate is not valid yet", "medium", {"not_before": c["not_before"]}, "Check the certificate's start date and the server clock."))
        if c.get("self_signed"):
            out.append(Obs(t, "cert_self_signed", "The certificate is self-signed", "medium", {"issuer": c["issuer"]}, "Use a certificate from a trusted authority for public services."))
        if c.get("key_type") == "RSA" and c.get("key_bits", 4096) < 2048:
            out.append(Obs(t, "weak_key", f"RSA key is only {c['key_bits']} bits", "high", {"key_bits": c["key_bits"]}, "Use an RSA key of at least 2048 bits or an ECDSA P-256 key."))
        if c.get("signature_hash") in ("md5", "sha1"):
            out.append(Obs(t, "weak_signature", f"The certificate is signed with {c['signature_hash'].upper()}", "medium", {"signature_hash": c["signature_hash"]}, "Reissue with a SHA-256 or stronger signature."))
        if probe.get("hostname_match") is False:
            out.append(Obs(t, "hostname_mismatch", "The certificate does not cover the host name", "medium", {"names": c.get("san", []), "host": probe.get("host")},
                           "Issue a certificate that lists this host name."))
    trust = probe.get("trust")
    if trust and trust != "ok" and not (c and c.get("self_signed")):
        out.append(Obs(t, "untrusted_chain", "The certificate chain is not trusted by this machine", "medium", {"detail": trust},
                       "Install the full chain on the server (including intermediates) or use a publicly trusted CA.", "observed", "medium"))
    if probe.get("cipher") and any(w in probe["cipher"].upper() for w in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")):
        out.append(Obs(t, "weak_cipher", f"A weak cipher was negotiated: {probe['cipher']}", "high", {"cipher": probe["cipher"]}, "Remove weak cipher suites."))
    out.append(Obs(t, "summary", "TLS handshake summary", "info", {"host": probe.get("host"), "port": probe.get("port"), "protocols": protos, "negotiated": probe.get("negotiated"),
                                                                    "cipher": probe.get("cipher"), "trust": trust}))
    return out


def port_observations(host: str, results: dict[int, str]) -> list[Obs]:
    out = []
    for port, state in sorted(results.items()):
        sev = "info"
        note = ""
        if state == "open" and port in (21, 23, 3389, 5900, 445, 3306, 5432, 6379, 27017, 9200, 11211):
            sev, note = "medium", "A service commonly not meant for the public internet accepts connections."
        out.append(Obs("tcp_port", f"port:{port}", f"TCP port {port} is {state.replace('_', ' ')}", sev, {"host": host, "port": port, "state": state},
                       "Close or firewall the port if the service is not intended to be public." if sev == "medium" else "",
                       "observed", "medium" if state == "filtered_or_unreachable" else "high"))
        if note:
            out[-1].observed["note"] = note
    return out

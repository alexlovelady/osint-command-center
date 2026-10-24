from __future__ import annotations

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("secret_scan", Path(__file__).parents[2] / "scripts" / "secret_scan.py")
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def scan(text: str) -> list[str]:
    return mod.scan_text(mod.ROOT / "x.py", text)


def test_detects_real_looking_credentials():
    assert scan("key = 'AKIAABCDEFGHIJKLMNOP'")
    assert scan("t = 'ghp_" + "a" * 36 + "'")
    assert scan("-----BEGIN RSA PRIVATE KEY-----")
    assert scan('password = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA=="')
    assert scan("Authorization: Bearer " + "A" * 40)


def test_ignores_fixtures_and_ordinary_code():
    assert not scan("TOKEN = 'e2e-token-local-only'")
    assert not scan("password = get_password(name)")
    assert not scan("secret: str = field(default_factory=lambda: os.environ.get('X'))")

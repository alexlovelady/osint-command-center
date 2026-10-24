"""Signing and serving app updates.

    uv run python scripts/update_tool.py keygen                       one-time: Ed25519 key pair (private key stays OUTSIDE the repo)
    uv run python scripts/update_tool.py publish --version 0.2.0 --notes "..." --base-url http://192.168.1.10:8800/ FILE [FILE ...]
    uv run python scripts/update_tool.py serve [--dir dist/update-server] [--host 127.0.0.1] [--port 8800]
    uv run python scripts/update_tool.py verify dist/update-server/manifest.json

`publish` copies the files into the server directory, hashes them, and writes `manifest.json`, a signed envelope the app verifies against
the public key built into it (`backend/osintcc/setup/update_key.pub`). The platform of each file is taken from its name (`win32`/`windows`/`.exe`
-> win32-x86_64, `linux` -> linux-x86_64). The server is a plain static file server: host the folder anywhere (this script, a NAS, any web server).
The app never installs an update by itself: it checks the signature, downloads, verifies the SHA-256, and tells you which file to run.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import shutil
import socketserver
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
PUB_FILE = ROOT / "backend" / "osintcc" / "setup" / "update_key.pub"


def default_key_path() -> Path:
    base = Path(os.environ.get("APPDATA") or Path.home() / ".config")
    return base / "osintcc-release" / "update-signing.key"


def platform_of(name: str) -> str:
    n = name.lower()
    if "linux" in n or n.endswith((".appimage", ".deb", ".tar.gz")):
        return "linux-x86_64"
    return "win32-x86_64"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_envelope(payload: dict, private_hex: str) -> dict:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    return {"payload": text, "signature": base64.b64encode(key.sign(text.encode())).decode()}


def load_private(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"signing key not found at {path}; run `update_tool.py keygen` first")
    return path.read_text(encoding="utf8").strip()


def cmd_keygen(a: argparse.Namespace) -> int:
    out = Path(a.out) if a.out else default_key_path()
    if out.exists() and not a.force:
        raise SystemExit(f"{out} already exists; refusing to overwrite (use --force only if you really mean to replace the key: every installed app would then reject updates)")
    key = Ed25519PrivateKey.generate()
    out.parent.mkdir(parents=True, exist_ok=True)
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    out.write_text(raw + "\n", encoding="utf8")
    try:
        out.chmod(0o600)
    except OSError:
        pass
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    PUB_FILE.write_text(pub + "\n", encoding="utf8")
    print(f"private key: {out}  (back it up somewhere safe; it is NOT in the repository)\npublic key:  {pub}\nwritten to {PUB_FILE} (commit this file; it is built into the app)")
    return 0


def cmd_publish(a: argparse.Namespace) -> int:
    if not re.fullmatch(r"\d{1,4}\.\d{1,4}\.\d{1,4}", a.version):
        raise SystemExit("version must look like 1.2.3")
    out = Path(a.dir)
    out.mkdir(parents=True, exist_ok=True)
    base = a.base_url if a.base_url.endswith("/") else a.base_url + "/"
    plats: dict[str, dict] = {}
    for f in a.files:
        src = Path(f)
        if not src.is_file():
            raise SystemExit(f"missing file {src}")
        name = re.sub(r"[^A-Za-z0-9._-]", "_", src.name)
        shutil.copy2(src, out / name)
        plats[platform_of(name)] = {"name": name, "url": base + name, "sha256": sha256(src), "size": src.stat().st_size}
    payload = {"version": a.version, "released": datetime.now(UTC).date().isoformat(), "notes": a.notes, "platforms": plats}
    env = sign_envelope(payload, load_private(Path(a.key) if a.key else default_key_path()))
    (out / "manifest.json").write_text(json.dumps(env, indent=1), encoding="utf8")
    print(f"published {a.version}: {', '.join(f'{p} -> {v['name']} ({v['size'] / 1e6:.1f} MB)' for p, v in plats.items())}\nmanifest: {out / 'manifest.json'}\n"
          f"point the app at {base}manifest.json (Settings -> Updates)")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    env = json.loads(Path(a.manifest).read_text(encoding="utf8"))
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUB_FILE.read_text(encoding="utf8").strip()))
    pub.verify(base64.b64decode(env["signature"]), env["payload"].encode())  # raises InvalidSignature
    print("signature OK:", json.loads(env["payload"])["version"])
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    d = Path(a.dir)
    d.mkdir(parents=True, exist_ok=True)
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(d))
    with socketserver.ThreadingTCPServer((a.host, a.port), handler) as srv:
        print(f"serving {d.resolve()} on http://{a.host}:{a.port}/  (static files only; Ctrl+C to stop)", flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out")
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("publish")
    p.add_argument("--version", required=True)
    p.add_argument("--notes", default="")
    p.add_argument("--base-url", required=True)
    p.add_argument("--dir", default=str(ROOT / "dist" / "update-server"))
    p.add_argument("--key")
    p.add_argument("files", nargs="+")
    p.set_defaults(fn=cmd_publish)
    v = sub.add_parser("verify")
    v.add_argument("manifest")
    v.set_defaults(fn=cmd_verify)
    s = sub.add_parser("serve")
    s.add_argument("--dir", default=str(ROOT / "dist" / "update-server"))
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8800)
    s.set_defaults(fn=cmd_serve)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

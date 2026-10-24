"""Freeze the backend into a single-file sidecar executable with PyInstaller.

    uv run python scripts/build_sidecar.py

Output: dist/sidecar/osintcc-backend[.exe] plus a copy named with the Rust target triple that Tauri's externalBin expects.
The frozen build includes the Alembic migrations as data files. It is NOT code-signed.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "sidecar"
SEP = ";" if sys.platform == "win32" else ":"
EXE = ".exe" if sys.platform == "win32" else ""


def triple() -> str:
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(platform.machine(), platform.machine())
    return {"win32": f"{arch}-pc-windows-msvc", "linux": f"{arch}-unknown-linux-gnu", "darwin": f"{arch}-apple-darwin"}[sys.platform]


def main() -> int:
    work = ROOT / "build" / "pyinstaller"
    OUT.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--name", "osintcc-backend",
        "--distpath", str(OUT), "--workpath", str(work), "--specpath", str(work),
        "--paths", str(ROOT / "backend"),
        "--add-data", f"{ROOT / 'backend' / 'osintcc' / 'db' / 'migrations'}{SEP}osintcc/db/migrations",
        "--add-data", f"{ROOT / 'backend' / 'osintcc' / 'setup' / 'catalog.json'}{SEP}osintcc/setup",
        "--add-data", f"{ROOT / 'backend' / 'osintcc' / 'setup' / 'requirements'}{SEP}osintcc/setup/requirements",
        "--collect-submodules", "osintcc", "--collect-all", "alembic", "--collect-all", "sqlcipher3",
        "--collect-submodules", "uvicorn", "--collect-submodules", "keyring.backends",
        "--hidden-import", "sqlalchemy.dialects.sqlite", "--collect-data", "reportlab",
        "--exclude-module", "tkinter", "--exclude-module", "pytest",
        str(ROOT / "scripts" / "sidecar_entry.py"),
    ]
    print(" ".join(cmd))
    if subprocess.run(cmd, cwd=ROOT, check=False).returncode != 0:
        return 1
    built = OUT / f"osintcc-backend{EXE}"
    shutil.copy2(built, OUT / f"osintcc-backend-{triple()}{EXE}")
    print(f"built {built} ({built.stat().st_size / 1e6:.1f} MB); triple copy: osintcc-backend-{triple()}{EXE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Assemble a PORTABLE release folder + zip + SHA256SUMS from already-built parts (no installer, no signing).

    uv run python scripts/release.py

Inputs (build them first):
    dist/sidecar/osintcc-backend[.exe]                         scripts/build_sidecar.py
    apps/desktop/src-tauri/target/release/osintcc-desktop[.exe] (cd apps/desktop && ../web/node_modules/.bin/tauri build --no-bundle)
Outputs: dist/release/OSINT-Command-Center-<version>-<platform>/, a .zip beside it, and SHA256SUMS.txt.

The result is UNSIGNED: Windows SmartScreen will warn. An NSIS/MSI installer needs the Tauri bundler to download its toolchain
and is deliberately not built here (see docs/packaging.md).
"""
from __future__ import annotations

import hashlib
import platform
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from osintcc import __version__

EXE = ".exe" if sys.platform == "win32" else ""


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if "--linux" in sys.argv:  # binaries produced by docker/linux-build/build.sh
        lin = ROOT / "dist" / "linux" / "linux"
        parts = {"osintcc-desktop": lin / "osintcc-desktop", "osintcc-backend": lin / "osintcc-backend"}
        plat_name = "linux"
    else:
        parts = {
            "osintcc-desktop" + EXE: ROOT / "apps/desktop/src-tauri/target/release" / f"osintcc-desktop{EXE}",
            "osintcc-backend" + EXE: ROOT / "dist/sidecar" / f"osintcc-backend{EXE}",
        }
        plat_name = sys.platform
    missing = [str(p) for p in parts.values() if not p.is_file()]
    if missing:
        print("missing build outputs:\n  " + "\n  ".join(missing))
        return 2
    name = f"OSINT-Command-Center-{__version__}-{plat_name}-{platform.machine().lower() if plat_name != 'linux' or sys.platform == 'linux' else 'x86_64'}"
    out = ROOT / "dist" / "release"
    folder = out / name
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    for dest, src in parts.items():
        shutil.copy2(src, folder / dest)
    for doc in ("README.md", "SECURITY.md"):
        shutil.copy2(ROOT / doc, folder / doc)
    (folder / "LICENSES-THIRD-PARTY.txt").write_text(
        "See docs/license-audit.md in the source tree for the dependency licence inventory.\n", encoding="utf8")
    sums = {p.name: sha256(p) for p in sorted(folder.iterdir()) if p.is_file()}
    (folder / "SHA256SUMS.txt").write_text("".join(f"{h}  {n}\n" for n, h in sums.items()), encoding="utf8")
    if plat_name == "linux":  # a tarball keeps the executable bits
        import tarfile
        zpath = out / f"{name}.tar.gz"
        with tarfile.open(zpath, "w:gz") as t:
            for p in sorted(folder.iterdir()):
                ti = t.gettarinfo(str(p), f"{name}/{p.name}")
                ti.mode = 0o755 if p.name.startswith("osintcc-") else 0o644
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                with p.open("rb") as fh:
                    t.addfile(ti, fh)
    else:
        zpath = out / f"{name}.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(folder.iterdir()):
                z.write(p, f"{name}/{p.name}")
    sums_file = out / "SHA256SUMS.txt"
    known: dict[str, str] = {}
    if sums_file.exists():
        for ln in sums_file.read_text(encoding="utf8").splitlines():
            h, _, n = ln.partition("  ")
            if n:
                known[n] = h
    known[zpath.name] = sha256(zpath)
    sums_file.write_text("".join(f"{h}  {n}\n" for n, h in sorted(known.items())), encoding="utf8")
    print(f"folder: {folder}\nzip:    {zpath} ({zpath.stat().st_size / 1e6:.1f} MB)\nsha256: {sha256(zpath)}")
    for n, h in sums.items():
        print(f"  {h}  {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

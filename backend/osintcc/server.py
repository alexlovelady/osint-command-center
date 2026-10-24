"""Backend entry point (loopback only).

    python -m osintcc.server [--dev-port]            headless API server (the desktop shell starts this)
    python -m osintcc.server mcp [mcp options]       MCP stdio server (spec 3.4)
    python -m osintcc.server setup [status|install|model] [--yes]   first-run tool and model setup
    osintcc-backend.exe --run-script FILE [args]     packaged builds only: run a reviewed plugin script in this interpreter

The last form exists because a frozen build has no separate `python` to hand to plugins. The host still verifies the
plugin's tree hash before launching it and mediates all of its network access.
"""
from __future__ import annotations

import os
import runpy
import sys


def _die_with_parent() -> None:
    """Linux: have the kernel SIGKILL this process when its parent exits (a PyInstaller one-file build runs as bootloader + child)."""
    if sys.platform.startswith("linux"):
        import contextlib
        import ctypes
        with contextlib.suppress(Exception):
            ctypes.CDLL(None).prctl(1, 9)  # PR_SET_PDEATHSIG, SIGKILL


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["mcp"]:
        from .mcp_server import main as mcp_main
        raise SystemExit(mcp_main(argv[1:]))
    if argv[:1] == ["setup"]:
        from .setup.__main__ import main as setup_main
        sys.argv = ["osintcc-setup", *argv[1:]]
        raise SystemExit(setup_main())
    if argv[:1] == ["--run-script"] and len(argv) >= 2:
        script = argv[1]
        sys.argv = [script, *argv[2:]]
        runpy.run_path(script, run_name="__main__")
        return
    from .main import run
    if getattr(sys, "frozen", False) or os.environ.get("OSINTCC_DIE_WITH_PARENT") == "1":
        _die_with_parent()
    run()


if __name__ == "__main__":
    main()

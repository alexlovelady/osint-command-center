"""Startup egress self-check: does this app's own process tree open outside connections while the user is doing nothing?

For a short window after launch (default 90 s) the application samples the operating system's connection table for itself and
every process it started (the desktop shell, the bundled backend, and the browser-engine processes the shell spawns) and records
which of them hold a connection to a non-loopback address. The verdict goes into the audit log and is shown on the Overview page.

What this is and is not:
* It is connection-level attribution, sampled every couple of seconds. It needs no administrator rights. It cannot see a packet that
  never became a socket the OS reports, and a connection that opens and closes between two samples can be missed. The packet-capture
  scripts (`scripts/egress_check.py`, `docker/linux-build/egress.sh`) remain the stronger evidence.
* Only the idle start-up window is judged. If the user (or a schedule) starts a search, a setup download or any job during the window,
  connections seen from then on are labelled as user-confirmed activity and do not fail the check.
* Connections made by the browser engine (Microsoft WebView2) are reported separately: they come from Microsoft's runtime, not this code.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psutil

ENGINE_NAMES = ("msedgewebview2", "webkitwebprocess", "webkitnetworkprocess", "webkit")
OUR_PREFIX = "osintcc"


@dataclass(frozen=True)
class Conn:
    process: str
    pid: int
    remote: str
    status: str


def _is_outside(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def process_tree() -> list[psutil.Process]:
    """The highest ancestor named osintcc* (the desktop shell when there is one) and everything below it."""
    me = psutil.Process()
    root = me
    while True:
        try:
            parent = root.parent()
        except psutil.Error:
            break
        if parent is None or not parent.name().lower().startswith(OUR_PREFIX):
            break
        root = parent
    try:
        return [root, *root.children(recursive=True)]
    except psutil.Error:
        return [me]


def snapshot() -> list[Conn]:
    out: list[Conn] = []
    for p in process_tree():
        try:
            name = p.name()
            for c in p.net_connections(kind="inet"):
                if c.raddr and _is_outside(c.raddr.ip) and c.status != psutil.CONN_LISTEN:
                    out.append(Conn(name, p.pid, f"{c.raddr.ip}:{c.raddr.port}", c.status))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out


def is_engine(process_name: str) -> bool:
    n = process_name.lower()
    return any(n.startswith(e) for e in ENGINE_NAMES)


class EgressMonitor:
    def __init__(self, *, window_s: float = 90.0, interval_s: float = 2.0, snap: Callable[[], list[Conn]] = snapshot,
                 busy: Callable[[], bool] = lambda: False, on_done: Callable[[dict[str, Any]], None] | None = None):
        self.window_s, self.interval_s, self.snap, self.busy, self.on_done = window_s, interval_s, snap, busy, on_done
        self.state: dict[str, Any] = {"enabled": True, "state": "pending", "window_s": window_s, "samples": 0, "verdict": None,
                                      "offenders": [], "engine_connections": [], "during_user_activity": [], "user_activity": False,
                                      "platform": os.name, "started_at": None, "finished_at": None, "note": ""}
        self._seen: dict[tuple, dict[str, Any]] = {}

    def sample_once(self) -> None:
        busy = self.busy()
        if busy:
            self.state["user_activity"] = True
        self.state["samples"] += 1
        for c in self.snap():
            key = (c.process, c.pid, c.remote, busy)
            if key in self._seen:
                continue
            kind = "during_user_activity" if busy else ("engine_connections" if is_engine(c.process) else "offenders")
            rec = {"process": c.process, "pid": c.pid, "remote": c.remote, "status": c.status, "first_seen": datetime.now(UTC).isoformat(timespec="seconds")}
            self._seen[key] = rec
            self.state[kind].append(rec)

    def finish(self) -> dict[str, Any]:
        st = self.state
        st["finished_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        st["state"] = "finished"
        if st["samples"] == 0:
            st["verdict"], st["note"] = "unavailable", "No samples could be taken on this system."
        elif st["offenders"]:
            st["verdict"] = "offending"
            st["note"] = "The app's own processes opened outside connections while idle. This should not happen: see the audit log and docs/privacy.md."
        elif st["engine_connections"]:
            st["verdict"] = "engine_only"
            st["note"] = ("Only the browser engine that draws the window connected outside (Microsoft WebView2 on Windows talks to Microsoft by itself). "
                          "The app's own code opened none.")
        else:
            st["verdict"] = "clean"
            st["note"] = "No outside connections from the app's processes during the start-up window."
        if st["user_activity"]:
            st["note"] += " Connections after you started an action are listed separately as user-confirmed activity."
        if self.on_done:
            self.on_done(st)
        return st

    async def run(self) -> None:
        self.state["state"], self.state["started_at"] = "running", datetime.now(UTC).isoformat(timespec="seconds")
        end = time.monotonic() + self.window_s
        try:
            while time.monotonic() < end:
                await asyncio.to_thread(self.sample_once)
                await asyncio.sleep(self.interval_s)
        except asyncio.CancelledError:
            self.state["state"], self.state["note"] = "interrupted", "The app was closed before the window ended."
            raise
        except Exception as exc:  # a broken probe must never take the app down
            self.state["note"] = f"probe error: {type(exc).__name__}"
        self.finish()

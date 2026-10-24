import stat
import sys

from osintcc import doctor


def _tool(tmp_path, monkeypatch, name, body, rc):
    if sys.platform == "win32":
        p = tmp_path / f"{name}.cmd"
        p.write_text(f"@echo off\r\necho {body}\r\nexit /b {rc}\r\n")
    else:
        p = tmp_path / name
        p.write_text(f"#!/bin/sh\necho '{body}'\nexit {rc}\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=";" if sys.platform == "win32" else ":")


def test_working_tool_reports_version(tmp_path, monkeypatch):
    _tool(tmp_path, monkeypatch, "faketool", "faketool 3.4.5 (build x)", 0)
    r = doctor._probe("faketool", ["--version"])
    assert r["found"] and r["works"] and r["version"] == "3.4.5"


def test_tool_on_path_but_failing_is_reported_broken_not_ok(tmp_path, monkeypatch):
    _tool(tmp_path, monkeypatch, "shimtool", "shimtool: node: not found", 127)
    r = doctor._probe("shimtool", ["--version"])
    assert r["found"] and r["works"] is False and r["version"].startswith("broken:")


def test_missing_tool_and_summary_logic(monkeypatch):
    assert doctor._probe("definitely-not-installed-xyz", []) == {"found": False}
    monkeypatch.setattr(doctor, "_probe", lambda n, a: {"found": True, "works": False, "version": "broken: x"} if n == "node" else {"found": True, "works": True, "version": "1.0"})
    rep = doctor.run_doctor()
    assert "node" in rep["summary"]["missing_required"] and "node" in rep["summary"]["broken"]

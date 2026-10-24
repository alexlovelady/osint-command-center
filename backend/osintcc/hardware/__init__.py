"""Hardware abstraction (spec 23.6).

The driver protocol is RECEIVE-ONLY by construction: there is no method that transmits, jams, spoofs or writes to a device.
Every driver can run without hardware (`simulate`/`import_capture`), so no installation or CI path ever needs a device.
Real-hardware code paths that have not been exercised against a physical device on this machine say so in `health()` and are
disabled unless the owner opts in.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import numpy as np


class DeviceGone(Exception):
    """The device disappeared mid-capture (USB removal). Partial data is kept."""

    def __init__(self, partial: CaptureResult | None = None):
        super().__init__("device disconnected during capture")
        self.partial = partial


class NotSupported(Exception):
    pass


@dataclass
class Discovered:
    hw_key: str
    logical_name: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CaptureResult:
    data: bytes
    filename: str
    kind: str  # parser kind to run on the artifact (sigmf | sensor_csv | ...)
    note: str = ""


class Handle:
    def __init__(self, device_key: str, scope: dict[str, Any], started: datetime):
        self.device_key, self.scope, self.started = device_key, scope, started
        self.unplugged = False


class Driver(Protocol):
    id: str
    device_kind: str
    simulated: bool
    receive_only: bool

    def discover(self) -> list[Discovered]: ...
    def capabilities(self, dev: Discovered) -> dict[str, Any]: ...
    def health(self) -> dict[str, Any]: ...
    def start_capture(self, dev: Discovered, scope: dict[str, Any]) -> Handle: ...
    def stop_capture(self, handle: Handle) -> CaptureResult: ...
    def import_capture(self, data: bytes, filename: str) -> CaptureResult: ...
    def disconnect(self, dev: Discovered) -> None: ...
    def simulate(self, seed: int = 0, **kw: Any) -> CaptureResult: ...


def _sigmf(iq: np.ndarray, fs: float, centre: float, desc: str, start: datetime) -> bytes:
    raw = np.empty(2 * len(iq), dtype="<f4")
    raw[0::2], raw[1::2] = iq.real, iq.imag
    meta = {"global": {"core:datatype": "cf32_le", "core:sample_rate": fs, "core:version": "1.0.0", "core:description": desc},
            "captures": [{"core:sample_start": 0, "core:frequency": centre, "core:datetime": start.strftime("%Y-%m-%dT%H:%M:%SZ")}],
            "annotations": []}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, d in (("capture.sigmf-meta", json.dumps(meta).encode()), ("capture.sigmf-data", raw.tobytes())):
            ti = tarfile.TarInfo(name)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


class SimSdrDriver:
    """Synthetic receiver: deterministic tone + noise. Labelled SIMULATION everywhere it appears."""
    id, device_kind, simulated, receive_only = "sim_sdr", "sdr", True, True
    FS = 48000.0

    def discover(self) -> list[Discovered]:
        return [Discovered("sim-sdr-0", "Simulated SDR (tone 1 kHz)", {"tone_hz": 1000.0, "centre_hz": 100e6}),
                Discovered("sim-sdr-flaky", "Simulated SDR (unplugs mid-capture)", {"tone_hz": 2000.0, "centre_hz": 100e6, "fault": "unplug"})]

    def capabilities(self, dev: Discovered) -> dict[str, Any]:
        return {"receive_only": True, "sample_rate_hz": self.FS, "max_capture_seconds": 30, "formats": ["sigmf"], "transmit": False,
                "simulated": True}

    def health(self) -> dict[str, Any]:
        return {"status": "healthy", "detail": "simulation: no hardware required", "verified_on_physical_device": False}

    def start_capture(self, dev: Discovered, scope: dict[str, Any]) -> Handle:
        h = Handle(dev.hw_key, scope, datetime.now(UTC))
        h.dev = dev  # type: ignore[attr-defined]
        return h

    def _iq(self, dev: Discovered, seconds: float, seed: int = 7) -> np.ndarray:
        n = int(self.FS * seconds)
        t = np.arange(n) / self.FS
        rng = np.random.default_rng(seed)
        sig = np.exp(2j * np.pi * dev.metadata["tone_hz"] * t) + 0.03 * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
        return sig.astype(np.complex64)

    def stop_capture(self, handle: Handle) -> CaptureResult:
        dev: Discovered = handle.dev  # type: ignore[attr-defined]
        secs = float(min(handle.scope.get("duration_s", 1), 30))
        if dev.metadata.get("fault") == "unplug":
            part = _sigmf(self._iq(dev, secs / 2), self.FS, dev.metadata["centre_hz"], "SIMULATED partial capture (device removed)", handle.started)
            raise DeviceGone(CaptureResult(part, "partial.sigmf", "sigmf", "device removed after 50% of the requested duration"))
        return CaptureResult(_sigmf(self._iq(dev, secs), self.FS, dev.metadata["centre_hz"], "SIMULATED tone capture", handle.started),
                             "capture.sigmf", "sigmf")

    def import_capture(self, data: bytes, filename: str) -> CaptureResult:
        return CaptureResult(data, filename, "sigmf")

    def disconnect(self, dev: Discovered) -> None:
        return None

    def simulate(self, seed: int = 0, **kw: Any) -> CaptureResult:
        d = Discovered("sim-sdr-0", "sim", {"tone_hz": float(kw.get("tone_hz", 1000.0)), "centre_hz": 100e6})
        return CaptureResult(_sigmf(self._iq(d, float(kw.get("seconds", 1.0)), seed), self.FS, 100e6, "SIMULATED", datetime.now(UTC)), "sim.sigmf", "sigmf")


class SimEsp32Driver:
    """Synthetic owner-operated environmental node (temperature) producing the standard sensor CSV."""
    id, device_kind, simulated, receive_only = "sim_esp32", "environmental", True, True

    def discover(self) -> list[Discovered]:
        return [Discovered("sim-esp32-0", "Simulated ESP32 environmental node", {"sensor": "SIMULATED-esp32", "unit": "degC"})]

    def capabilities(self, dev: Discovered) -> dict[str, Any]:
        return {"receive_only": True, "formats": ["sensor_csv"], "interval_s": 60, "max_samples": 5000, "simulated": True}

    def health(self) -> dict[str, Any]:
        return {"status": "healthy", "detail": "simulation: no hardware required", "verified_on_physical_device": False}

    def start_capture(self, dev: Discovered, scope: dict[str, Any]) -> Handle:
        h = Handle(dev.hw_key, scope, datetime.now(UTC))
        h.dev = dev  # type: ignore[attr-defined]
        return h

    def _csv(self, n: int, seed: int, anomaly: bool = False) -> bytes:
        rng = np.random.default_rng(seed)
        t0 = datetime(2026, 1, 1, tzinfo=UTC)
        rows = ["timestamp,value,unit,sensor"]
        for i in range(n):
            v = 20.0 + float(rng.normal(0, 0.1)) + (8.0 if anomaly and n // 2 <= i < n // 2 + 4 else 0.0)
            rows.append(f"{(t0 + timedelta(minutes=i)).isoformat()},{v:.4f},degC,SIMULATED-esp32")
        return "\n".join(rows).encode()

    def stop_capture(self, handle: Handle) -> CaptureResult:
        n = int(min(max(handle.scope.get("duration_s", 60), 20), 5000))
        return CaptureResult(self._csv(n, 3, anomaly=True), "esp32.csv", "sensor_csv")

    def import_capture(self, data: bytes, filename: str) -> CaptureResult:
        return CaptureResult(data, filename, "sensor_csv")

    def disconnect(self, dev: Discovered) -> None:
        return None

    def simulate(self, seed: int = 0, **kw: Any) -> CaptureResult:
        return CaptureResult(self._csv(int(kw.get("samples", 120)), seed, bool(kw.get("anomaly", True))), "sim.csv", "sensor_csv")


class ReplayDriver:
    """Replays a recording the analyst already has (`import_capture`). No device involved."""
    id, device_kind, simulated, receive_only = "replay", "replay", True, True

    def discover(self) -> list[Discovered]:
        return [Discovered("replay-0", "Replay of an existing recording", {})]

    def capabilities(self, dev: Discovered) -> dict[str, Any]:
        return {"receive_only": True, "formats": ["sigmf", "sensor_csv", "pcap", "ccsds", "adsb", "ais", "gps_nmea"], "simulated": True}

    def health(self) -> dict[str, Any]:
        return {"status": "healthy", "detail": "no hardware", "verified_on_physical_device": False}

    def start_capture(self, dev: Discovered, scope: dict[str, Any]) -> Handle:
        raise NotSupported("the replay driver imports existing files; use import_capture")

    def stop_capture(self, handle: Handle) -> CaptureResult:
        raise NotSupported("nothing to stop")

    def import_capture(self, data: bytes, filename: str) -> CaptureResult:
        from ..ingest import parsers
        kind = parsers.detect_kind(filename, data[:512])
        if not kind:
            raise NotSupported("cannot tell what this recording is; import it from the Imports tab and choose its type")
        return CaptureResult(data, filename, kind)

    def disconnect(self, dev: Discovered) -> None:
        return None

    def simulate(self, seed: int = 0, **kw: Any) -> CaptureResult:
        raise NotSupported("replay has nothing to simulate")


class RtlSdrDriver:
    """RTL-SDR via pyrtlsdr when installed. Discovery is read-only. The capture path below has NOT been run against a physical
    device here, so it is off unless OSINTCC_ALLOW_UNVERIFIED_HW=1 and the health report says so."""
    id, device_kind, simulated, receive_only = "rtlsdr", "sdr", False, True

    def _lib(self):
        try:
            import rtlsdr
            return rtlsdr
        except Exception:
            return None

    def discover(self) -> list[Discovered]:
        lib = self._lib()
        if lib is None:
            return []
        try:
            out = []
            for i, serial in enumerate(lib.RtlSdr.get_device_serial_addresses()):
                out.append(Discovered(hashlib.sha256(str(serial).encode()).hexdigest()[:16], f"RTL-SDR #{i}", {"index": i}))
            return out
        except Exception:
            return []

    def capabilities(self, dev: Discovered) -> dict[str, Any]:
        return {"receive_only": True, "sample_rate_hz": 2.4e6, "max_capture_seconds": 30, "formats": ["sigmf"], "transmit": False, "simulated": False}

    def health(self) -> dict[str, Any]:
        if self._lib() is None:
            return {"status": "not_installed", "verified_on_physical_device": False,
                    "detail": "pyrtlsdr is not installed",
                    "remediation": ["pip/uv add pyrtlsdr (in an environment you control)", "Windows: install the WinUSB driver for the dongle with Zadig",
                                    "Linux: add a udev rule granting your user access to the RTL2832U device (vendor 0bda)"]}
        return {"status": "degraded" if os.environ.get("OSINTCC_ALLOW_UNVERIFIED_HW") != "1" else "healthy",
                "verified_on_physical_device": False,
                "detail": "library present; capture is disabled until OSINTCC_ALLOW_UNVERIFIED_HW=1 because it has not been tested on hardware here"}

    def start_capture(self, dev: Discovered, scope: dict[str, Any]) -> Handle:
        if os.environ.get("OSINTCC_ALLOW_UNVERIFIED_HW") != "1":
            raise NotSupported("RTL-SDR capture is unverified on this machine; set OSINTCC_ALLOW_UNVERIFIED_HW=1 to try it at your own risk")
        h = Handle(dev.hw_key, scope, datetime.now(UTC))
        h.dev = dev  # type: ignore[attr-defined]
        return h

    def stop_capture(self, handle: Handle) -> CaptureResult:  # UNVERIFIED on physical hardware
        lib = self._lib()
        if lib is None:
            raise NotSupported("pyrtlsdr not installed")
        dev: Discovered = handle.dev  # type: ignore[attr-defined]
        sdr = None
        try:
            sdr = lib.RtlSdr(device_index=dev.metadata["index"])
            fs, centre = 2.4e6, float(handle.scope.get("centre_hz", 100e6))
            sdr.sample_rate, sdr.center_freq = fs, centre
            n = int(fs * min(float(handle.scope.get("duration_s", 1)), 5))
            iq = np.asarray(sdr.read_samples(n), dtype=np.complex64)
        except Exception as exc:
            raise DeviceGone() from exc
        finally:
            if sdr is not None:
                sdr.close()
        return CaptureResult(_sigmf(iq, fs, centre, "RTL-SDR capture (receive only)", handle.started), "rtlsdr.sigmf", "sigmf")

    def import_capture(self, data: bytes, filename: str) -> CaptureResult:
        return CaptureResult(data, filename, "sigmf")

    def disconnect(self, dev: Discovered) -> None:
        return None

    def simulate(self, seed: int = 0, **kw: Any) -> CaptureResult:
        return SimSdrDriver().simulate(seed, **kw)


def default_drivers() -> dict[str, Driver]:
    ds: list[Driver] = [SimSdrDriver(), SimEsp32Driver(), ReplayDriver(), RtlSdrDriver()]
    return {d.id: d for d in ds}

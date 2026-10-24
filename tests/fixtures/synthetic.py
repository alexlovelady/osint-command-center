"""Generators for SYNTHETIC fixtures. Everything here is fabricated test data, never a real recording or message."""
from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime, timedelta

import numpy as np


def sigmf_archive(tone_hz: float = 1000.0, fs: float = 48000.0, n: int = 1 << 16, centre: float = 100e6,
                  datatype: str = "cf32_le", meta_override: dict | None = None, snr_db: float = 30.0,
                  seed: int = 7) -> bytes:
    rng = np.random.default_rng(seed)
    t = np.arange(n) / fs
    sig = np.exp(2j * np.pi * tone_hz * t) + 10 ** (-snr_db / 20) * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    sig = sig.astype(np.complex64)
    raw = np.empty(2 * n, dtype="<f4")
    raw[0::2], raw[1::2] = sig.real, sig.imag
    meta = {"global": {"core:datatype": datatype, "core:sample_rate": fs, "core:version": "1.0.0",
                       "core:description": "SYNTHETIC test tone"},
            "captures": [{"core:sample_start": 0, "core:frequency": centre, "core:datetime": "2026-01-01T00:00:00Z"}],
            "annotations": []}
    if meta_override is not None:
        meta = meta_override
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in (("synthetic.sigmf-meta", json.dumps(meta).encode()), ("synthetic.sigmf-data", raw.tobytes())):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


EML_HTML = b"""From: Alice Example <alice@Example.com>
To: Bob <bob@example.org>, carol@example.net
Cc: dave@example.org
Subject: SYNTHETIC quarterly note
Date: Tue, 02 Jan 2024 10:30:00 +0000
Message-ID: <synthetic-1@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/html; charset=utf-8

<html><body><p>Hello <b>Bob</b></p><script>alert(1)</script><img src="http://tracker.invalid/x.png"></body></html>
--B
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--B--
"""


def sensor_csv(anomaly: bool = True, n: int = 200) -> bytes:
    rng = np.random.default_rng(3)
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    rows = ["timestamp,value,unit,sensor"]
    for i in range(n):
        v = 20.0 + rng.normal(0, 0.1)
        if anomaly and 100 <= i < 105:
            v += 8.0
        rows.append(f"{(t0 + timedelta(minutes=i)).isoformat()},{v:.4f},degC,SYNTHETIC-esp32")
    return "\n".join(rows).encode()

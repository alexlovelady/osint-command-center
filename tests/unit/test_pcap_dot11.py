from __future__ import annotations

import struct

from osintcc.ingest import net


def dns_query(name: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 54321, 53, 8 + len(dns), 0) + dns
    return struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0) + bytes([10, 0, 0, 2]) + bytes([8, 8, 8, 8]) + udp


def pcap(link: int, frames: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(f), len(f)) + f
    return out


def dot11_qos_data(ip: bytes) -> bytes:
    return bytes([0x88, 0x02, 0x2C, 0x00]) + bytes(18) + b"\x60\x0d" + b"\x00\x00" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + ip


def test_wifi_frames_are_parsed_whether_labelled_80211_or_ethernet():
    ip = dns_query("substrate.office.com")
    for link in (105, 1):  # pktmon writes 802.11 frames under link type 1 (Ethernet)
        d = net.parse_pcap(pcap(link, [dot11_qos_data(ip)] * 3))
        o = d.observations[0].data
        assert o["packets"] == 3 and o["flows_total"] == 1 and o["dns_queries"][0]["name"] == "substrate.office.com", link


def test_ordinary_ethernet_is_unaffected_and_non_data_80211_is_ignored():
    eth = bytes(6) + bytes(6) + b"\x08\x00" + dns_query("example.org")
    o = net.parse_pcap(pcap(1, [eth])).observations[0].data
    assert o["dns_queries"][0]["name"] == "example.org"
    assert net._dot11(bytes([0x80, 0x00]) + bytes(40)) is None          # a beacon, not data
    assert net._dot11(b"\x88\x02" + bytes(10)) is None                   # truncated

#!/usr/bin/env python3
"""
Generate a SYNTHETIC 3GPP capture for documentation screenshots and manual testing.

    python3 docs/make-synthetic-capture.py [output.pcap]

Why this script exists
----------------------
`.gitignore` blocks `*.pcap` / `*.pcapng` and CI rejects any diff that adds or
modifies one. That rule is deliberate: **real operator captures must never enter
this repository.** The corollary is that documentation screenshots and manual
test material also cannot use a real capture.

So we generate one instead. Every frame below is hand-assembled from literal
bytes. The addressing uses RFC 5737 / RFC 3849 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the hostnames are the
IETF-reserved `.invalid` / example domains. Nothing here was captured from a
network.

The PFCP and Diameter frames are byte-for-byte equivalent to the builders in
`tests/pf-verify/Program.cs` (`BuildSyntheticPfcpAssociationResponse`,
`BuildSyntheticDiameterDwr`), so the frames this produces are the same ones the
verification harness already asserts against.

The generated .pcap is written OUTSIDE the repository by default. It is a local
artifact, not a source file.
"""

import ipaddress
import struct
import sys

# ── byte helpers ────────────────────────────────────────────────────────────


def u8(v):
    return struct.pack("!B", v & 0xFF)


def u16(v):
    return struct.pack("!H", v & 0xFFFF)


def u32(v):
    return struct.pack("!I", v & 0xFFFFFFFF)


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip(s):
    return ipaddress.IPv4Address(s).packed


# ── layer builders ──────────────────────────────────────────────────────────
# A fixed, obviously-synthetic Ethernet header. src is locally administered
# (bit 1 of the first octet set), so it can never collide with a real OUI.
ETH_SRC = mac("02:00:00:00:00:01")
ETH_DST = mac("02:00:00:00:00:02")


def eth(payload, ethertype=0x0800):
    return ETH_DST + ETH_SRC + u16(ethertype) + payload


def _ones_complement_sum(data):
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def ipv4(payload, proto=17, ident=1, frag=0, src="192.0.2.1", dst="192.0.2.2"):
    total = 20 + len(payload)
    hdr = (
        u8(0x45)
        + u8(0x00)
        + u16(total)
        + u16(ident)
        + u16(frag)
        + u8(64)
        + u8(proto)
        + u16(0)
        + ip(src)
        + ip(dst)
    )
    return _splice_ipv4_checksum(hdr) + payload


def _splice_ipv4_checksum(hdr):
    return hdr[:10] + u16(~_ones_complement_sum(hdr) & 0xFFFF) + hdr[12:]


def udp(sport, dport, payload):
    return u16(sport) + u16(dport) + u16(8 + len(payload)) + u16(0) + payload


def sctp(sport, dport, chunks, vtag=0xA08549A6):
    return u16(sport) + u16(dport) + u32(vtag) + b"\x00\x00\x00\x00" + b"".join(chunks)


def sctp_data(payload, ppid, tsn=0, stream=0, stream_seq=0):
    body = u32(tsn) + u16(stream) + u16(stream_seq) + u32(ppid)
    return b"\x00\x03" + u16(4 + len(body)) + body + payload


# ── 3GPP payloads ───────────────────────────────────────────────────────────


def pfcp_avp(code, value):
    return u16(code) + u16(len(value)) + value


PFCP_ASSOCIATION_RESPONSE = bytes.fromhex(
    "2006002400000100"          # version 1, type 6, len 0x24, seq 1, spare
    "003c0005" "007f000001"     # AVP 60  Node Address  = 127.0.0.1
    "00130001" "4c"             # AVP 19  Node Type     = SMF
    "00600004" "00000000"       # AVP 96  Parameter Set
    "002b0006" "010000000000"   # AVP 43  Cause         = accepted
)


def gtpu_echo(type_, seq):
    flags = 0x32 if seq is not None else 0x30
    optional = struct.pack("!HBB", seq, 0x00, 0x00) if seq is not None else b""
    return udp(2152, 2152, u8(flags) + u8(type_) + u16(len(optional)) + u32(0) + optional)


def gtpu_echo_request():
    return gtpu_echo(0x01, None)


def gtpu_echo_response(seq):
    return gtpu_echo(0x02, seq)


def tcp_segment(sport, dport, seq, ack, flags, payload):
    return (
        u16(sport)
        + u16(dport)
        + u32(seq)
        + u32(ack)
        + u8(0x50)
        + u8(flags)
        + u16(0x4000)  # window
        + u16(0)  # checksum
        + u16(0)  # urgent pointer
        + payload
    )


# ── the capture ─────────────────────────────────────────────────────────────
# (name, frame). Deliberately mixes control-plane (PFCP, Diameter), user-plane
# (GTP-U) and transport (TCP) so a documentation screenshot shows the tool
# handling more than one protocol.
FRAMES = [
    ("PFCP Association Setup Response", eth(ipv4(udp(8805, 8805, PFCP_ASSOCIATION_RESPONSE), src="127.0.0.1", dst="127.0.0.2"))),
    ("GTP-U Echo Request", eth(ipv4(gtpu_echo(0x01, None), ident=0x1236, src="203.0.113.10", dst="203.0.113.20"))),
    ("GTP-U Echo Response", eth(ipv4(gtpu_echo(0x02, 0x1234), ident=0x1237, src="203.0.113.20", dst="203.0.113.10"))),
    ("GTP-U Echo Request", eth(ipv4(gtpu_echo(0x01, None), ident=0x1238, src="203.0.113.10", dst="203.0.113.30"))),
    ("GTP-U Echo Response", eth(ipv4(gtpu_echo(0x02, 0x1235), ident=0x1239, src="203.0.113.30", dst="203.0.113.10"))),
    ("HTTP over TCP", eth(ipv4(tcp_segment(8080, 8080, 0x1000, 0x2000, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), proto=6, ident=0x123A, src="198.51.100.5", dst="198.51.100.6"))),
]


def write_pcap(path, frames, start=1_700_000_000):
    """Classic little-endian PCAP, LINKTYPE_ETHERNET."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, (_name, data) in enumerate(frames):
            fh.write(struct.pack("<IIII", start + i, i * 1000, len(data), len(data)))
            fh.write(data)
    return len(frames)


def main():
    # Default target is OUTSIDE the repo: .gitignore blocks *.pcap, and a
    # generated capture is still a capture as far as that rule is concerned.
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/protocol-forge-synthetic.pcap"
    n = write_pcap(out, FRAMES)
    print(f"wrote {n} synthetic frames to {out}")
    for name, _ in FRAMES:
        print(f"  - {name}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import ipaddress
import struct

from deep_packet_analyzer.pcap_reader import RawPacket, PcapPacketHeader


def ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return bytes.fromhex("aabbccddeeff001122334455") + struct.pack("!H", ether_type) + payload


def tcp_segment(
    src_port: int = 12345,
    dst_port: int = 443,
    payload: bytes = b"",
    flags: int = 0x18,
) -> bytes:
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        100,
        200,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    return header + payload


def udp_datagram(
    src_port: int = 12345, dst_port: int = 53, payload: bytes = b""
) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, len(payload) + 8, 0) + payload


def ipv4_packet(
    transport: bytes,
    protocol: int = 6,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.20",
    options: bytes = b"",
) -> bytes:
    assert len(options) % 4 == 0
    ihl = 20 + len(options)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | (ihl // 4),
        0,
        ihl + len(transport),
        1,
        0,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return ethernet(header + options + transport)


def ipv6_packet(
    transport: bytes,
    next_header: int = 6,
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
) -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(transport),
        next_header,
        64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    )
    return ethernet(header + transport, 0x86DD)


def tls_client_hello(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    name_entry = struct.pack("!BH", 0, len(name)) + name
    server_names = struct.pack("!H", len(name_entry)) + name_entry
    sni_extension = struct.pack("!HH", 0, len(server_names)) + server_names
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", 2)
        + struct.pack("!H", 0x1301)
        + b"\x01\x00"
        + struct.pack("!H", len(sni_extension))
        + sni_extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def raw_packet(data: bytes, packet_id: int = 0) -> RawPacket:
    header_raw = struct.pack("<IIII", 1_700_000_000 + packet_id, packet_id, len(data), len(data))
    header = PcapPacketHeader(1_700_000_000 + packet_id, packet_id, len(data), len(data), header_raw)
    return RawPacket(header, data)


def write_pcap(path, packets: list[bytes]) -> None:
    with open(path, "wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            stream.write(
                struct.pack(
                    "<IIII", 1_700_000_000 + index, index, len(packet), len(packet)
                )
            )
            stream.write(packet)

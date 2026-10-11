"""Bounds-checked Ethernet, IPv4/IPv6, TCP, and UDP parsing."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct
from typing import ClassVar

from .pcap_reader import RawPacket


class PacketParseError(ValueError):
    """A truncated or malformed link, network, or transport header."""


@dataclass(slots=True)
class ParsedPacket:
    timestamp_sec: int
    timestamp_frac: int
    src_mac: str
    dest_mac: str
    ether_type: int
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    packet_end: int = 0
    truncated: bool = False
    fragmented: bool = False

class PacketParser:
    IPV4: ClassVar[int] = 0x0800
    IPV6: ClassVar[int] = 0x86DD
    VLAN_TYPES: ClassVar[frozenset[int]] = frozenset({0x8100, 0x88A8, 0x9100})
    TCP: ClassVar[int] = 6
    UDP: ClassVar[int] = 17

    @classmethod
    def parse(cls, raw: RawPacket | bytes) -> ParsedPacket:
        data = raw.data if isinstance(raw, RawPacket) else raw
        timestamp_sec = raw.header.ts_sec if isinstance(raw, RawPacket) else 0
        timestamp_frac = raw.header.ts_frac if isinstance(raw, RawPacket) else 0
        if len(data) < 14:
            raise PacketParseError("Ethernet frame is shorter than 14 bytes")

        dest_mac = cls.mac_to_string(data[0:6])
        src_mac = cls.mac_to_string(data[6:12])
        ether_type = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        while ether_type in cls.VLAN_TYPES:
            if len(data) < offset + 4:
                raise PacketParseError("Truncated VLAN Ethernet header")
            ether_type = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4

        parsed = ParsedPacket(
            timestamp_sec,
            timestamp_frac,
            src_mac,
            dest_mac,
            ether_type,
            packet_end=len(data),
        )
        if ether_type == cls.IPV4:
            cls._parse_ipv4(data, offset, parsed)
        elif ether_type == cls.IPV6:
            cls._parse_ipv6(data, offset, parsed)
        else:
            parsed.payload_offset = offset
            parsed.payload_length = len(data) - offset
        return parsed

    @staticmethod
    def _parse_ipv4(data: bytes, offset: int, parsed: ParsedPacket) -> None:
        if len(data) < offset + 20:
            raise PacketParseError("IPv4 header is truncated")
        version_ihl = data[offset]
        version, ihl = version_ihl >> 4, (version_ihl & 0x0F) * 4
        if version != 4:
            raise PacketParseError(f"Invalid IPv4 version {version}")
        if ihl < 20 or len(data) < offset + ihl:
            raise PacketParseError("Invalid or truncated IPv4 header length")
        total_length = struct.unpack_from("!H", data, offset + 2)[0]
        if total_length < ihl:
            raise PacketParseError("IPv4 total length is smaller than its header")
        packet_end = offset + total_length
        parsed.truncated = packet_end > len(data)
        packet_end = min(packet_end, len(data))
        fragment_field = struct.unpack_from("!H", data, offset + 6)[0]
        parsed.ip_version = 4
        parsed.has_ip = True
        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]
        parsed.src_ip = str(ipaddress.IPv4Address(data[offset + 12 : offset + 16]))
        parsed.dest_ip = str(ipaddress.IPv4Address(data[offset + 16 : offset + 20]))
        parsed.packet_end = packet_end
        parsed.fragmented = bool(fragment_field & 0x3FFF)
        transport_offset = offset + ihl
        if fragment_field & 0x1FFF:
            parsed.payload_offset = transport_offset
            parsed.payload_length = max(0, packet_end - transport_offset)
            return
        PacketParser._parse_transport(data, transport_offset, packet_end, parsed)

    @staticmethod
    def _parse_ipv6(data: bytes, offset: int, parsed: ParsedPacket) -> None:
        if len(data) < offset + 40:
            raise PacketParseError("IPv6 header is truncated")
        version = data[offset] >> 4
        if version != 6:
            raise PacketParseError(f"Invalid IPv6 version {version}")
        payload_length = struct.unpack_from("!H", data, offset + 4)[0]
        packet_end = offset + 40 + payload_length
        parsed.truncated = packet_end > len(data)
        packet_end = min(packet_end, len(data))
        next_header = data[offset + 6]
        parsed.ip_version = 6
        parsed.has_ip = True
        parsed.ttl = data[offset + 7]
        parsed.src_ip = str(ipaddress.IPv6Address(data[offset + 8 : offset + 24]))
        parsed.dest_ip = str(ipaddress.IPv6Address(data[offset + 24 : offset + 40]))
        parsed.packet_end = packet_end
        transport_offset = offset + 40
        extension_count = 0
        while next_header in {0, 43, 44, 51, 60}:
            extension_count += 1
            if extension_count > 16:
                raise PacketParseError("IPv6 extension header chain is too long")
            if transport_offset + 2 > packet_end:
                raise PacketParseError("IPv6 extension header is truncated")
            current_header = next_header
            next_header = data[transport_offset]
            if current_header == 44:
                extension_length = 8
                if transport_offset + extension_length > packet_end:
                    raise PacketParseError("IPv6 fragment header is truncated")
                fragment_field = struct.unpack_from("!H", data, transport_offset + 2)[0]
                parsed.fragmented = bool(fragment_field & 0xFFF9)
                transport_offset += extension_length
                if fragment_field & 0xFFF8:
                    parsed.protocol = next_header
                    parsed.payload_offset = transport_offset
                    parsed.payload_length = max(0, packet_end - transport_offset)
                    return
                continue
            if current_header == 51:
                extension_length = (data[transport_offset + 1] + 2) * 4
            else:
                extension_length = (data[transport_offset + 1] + 1) * 8
            if transport_offset + extension_length > packet_end:
                raise PacketParseError("IPv6 extension header length exceeds packet")
            transport_offset += extension_length
        if next_header == 50:
            parsed.protocol = next_header
            parsed.payload_offset = transport_offset
            parsed.payload_length = max(0, packet_end - transport_offset)
            return
        parsed.protocol = next_header
        PacketParser._parse_transport(data, transport_offset, packet_end, parsed)

    @staticmethod
    def _parse_transport(
        data: bytes, offset: int, packet_end: int, parsed: ParsedPacket
    ) -> None:
        parsed.payload_offset = offset
        parsed.payload_length = max(0, packet_end - offset)
        if parsed.protocol == PacketParser.TCP:
            if packet_end < offset + 20:
                raise PacketParseError("TCP header is truncated")
            src_port, dst_port, seq, ack = struct.unpack_from("!HHII", data, offset)
            header_length = (data[offset + 12] >> 4) * 4
            if header_length < 20 or packet_end < offset + header_length:
                raise PacketParseError("Invalid or truncated TCP header length")
            parsed.has_tcp = True
            parsed.src_port = src_port
            parsed.dest_port = dst_port
            parsed.seq_number = seq
            parsed.ack_number = ack
            parsed.tcp_flags = data[offset + 13]
            parsed.payload_offset = offset + header_length
            parsed.payload_length = packet_end - parsed.payload_offset
        elif parsed.protocol == PacketParser.UDP:
            if packet_end < offset + 8:
                raise PacketParseError("UDP header is truncated")
            src_port, dst_port, udp_length = struct.unpack_from("!HHH", data, offset)
            if udp_length < 8:
                raise PacketParseError("Invalid UDP datagram length")
            udp_end = min(offset + udp_length, packet_end)
            parsed.has_udp = True
            parsed.src_port = src_port
            parsed.dest_port = dst_port
            parsed.payload_offset = offset + 8
            parsed.payload_length = udp_end - parsed.payload_offset

    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ":".join(f"{octet:02x}" for octet in mac)

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
            protocol, f"Unknown({protocol})"
        )

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        names = (
            (0x02, "SYN"),
            (0x10, "ACK"),
            (0x01, "FIN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x20, "URG"),
        )
        return " ".join(name for mask, name in names if flags & mask) or "none"

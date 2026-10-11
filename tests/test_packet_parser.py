import struct

import pytest

from deep_packet_analyzer.packet_parser import PacketParseError, PacketParser
from deep_packet_analyzer.pcap_reader import RawPacket

from helpers import ethernet, ipv4_packet, ipv6_packet, raw_packet, tcp_segment, udp_datagram


def test_parses_ethernet_ipv4_tcp_and_payload_offsets():
    frame = ipv4_packet(tcp_segment(payload=b"hello"))
    parsed = PacketParser.parse(raw_packet(frame))
    assert parsed.src_mac == "00:11:22:33:44:55"
    assert parsed.dest_mac == "aa:bb:cc:dd:ee:ff"
    assert parsed.src_ip == "192.0.2.10"
    assert parsed.dest_ip == "198.51.100.20"
    assert parsed.src_port == 12345
    assert parsed.dest_port == 443
    assert parsed.tcp_flags == 0x18
    assert frame[parsed.payload_offset : parsed.payload_offset + parsed.payload_length] == b"hello"


def test_parses_ipv4_options_and_udp():
    frame = ipv4_packet(udp_datagram(payload=b"dns"), protocol=17, options=b"\x00" * 4)
    parsed = PacketParser.parse(frame)
    assert parsed.ip_version == 4
    assert parsed.has_udp
    assert parsed.src_port == 12345
    assert parsed.dest_port == 53
    assert frame[parsed.payload_offset : parsed.payload_offset + parsed.payload_length] == b"dns"


def test_parses_ipv6_tcp_and_extension_header():
    tcp = tcp_segment(payload=b"v6")
    frame = ipv6_packet(b"\x06\x00" + b"\x00" * 6 + tcp, next_header=0)
    parsed = PacketParser.parse(frame)
    assert parsed.ip_version == 6
    assert parsed.src_ip == "2001:db8::1"
    assert parsed.dest_ip == "2001:db8::2"
    assert parsed.has_tcp
    assert frame[parsed.payload_offset : parsed.payload_offset + parsed.payload_length] == b"v6"


def test_parses_ipv6_udp():
    parsed = PacketParser.parse(ipv6_packet(udp_datagram(payload=b"query"), next_header=17))
    assert parsed.has_udp
    assert parsed.dest_port == 53
    assert parsed.payload_length == 5


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\x00" * 13,
        ethernet(b"\x45" * 10),
        ipv4_packet(b"\x00" * 19, protocol=6),
        ipv4_packet(b"\x00" * 7, protocol=17),
    ],
)
def test_rejects_malformed_and_truncated_frames(frame):
    with pytest.raises(PacketParseError):
        PacketParser.parse(frame)


def test_marks_truncated_network_payload_without_reading_out_of_bounds():
    frame = ipv4_packet(tcp_segment(payload=b"abc"))[:-2]
    parsed = PacketParser.parse(frame)
    assert parsed.truncated
    assert parsed.payload_length == 1


def test_vlan_frame_is_parsed():
    inner = ipv4_packet(tcp_segment())
    vlan_frame = inner[:12] + struct.pack("!HHH", 0x8100, 10, 0x0800) + inner[14:]
    parsed = PacketParser.parse(vlan_frame)
    assert parsed.has_tcp


def test_non_ip_ethernet_is_reported_without_transport():
    parsed = PacketParser.parse(ethernet(b"\x00" * 28, ether_type=0x0806))
    assert not parsed.has_ip
    assert not parsed.has_tcp

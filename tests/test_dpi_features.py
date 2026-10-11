import os
import ipaddress
from pathlib import Path
import subprocess
import sys
import time

import pytest

from deep_packet_analyzer.connection_tracker import ConnectionTracker
from deep_packet_analyzer.packet_parser import PacketParser
from deep_packet_analyzer.pcap_reader import PcapReader
from deep_packet_analyzer.rule_manager import RuleManager
from deep_packet_analyzer.sni_extractor import (
    QUICSNIExtractor,
    extract_dns_query,
    extract_http_host,
    extract_sni,
    is_tls_client_hello,
)
from deep_packet_analyzer.thread_safe_queue import ThreadSafeQueue
from deep_packet_analyzer.types import AppType, FiveTuple
from deep_packet_analyzer.types import sni_to_app_type

from helpers import (
    ipv4_packet,
    raw_packet,
    tcp_segment,
    tls_client_hello,
    udp_datagram,
    write_pcap,
)


def test_tls_sni_http_host_and_dns_query_extractors():
    hello = tls_client_hello("www.youtube.com")
    assert is_tls_client_hello(hello)
    assert extract_sni(hello) == "www.youtube.com"
    assert sni_to_app_type("www.youtube.com") == AppType.YOUTUBE
    assert extract_sni(hello[:20]) is None
    assert extract_http_host(
        b"GET / HTTP/1.1\r\nhOsT: example.com:8080\r\n\r\n"
    ) == "example.com"
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x03www\x06google\x03com\x00\x00\x01\x00\x01"
    )
    assert extract_dns_query(query) == "www.google.com"
    assert extract_dns_query(query[:15]) is None


def test_connection_tracking_and_eviction():
    first = FiveTuple(
        ipaddress.ip_address("192.0.2.1"),
        ipaddress.ip_address("198.51.100.2"),
        1000,
        443,
        6,
    )
    second = first.reverse()
    tracker = ConnectionTracker(fp_id=1, max_connections=1)
    connection = tracker.get_or_create_connection(first)
    tracker.update_connection(connection, 100)
    assert connection.packets_out == 1
    assert tracker.get_connection(first) is connection
    tracker.get_or_create_connection(second)
    assert tracker.get_active_count() == 1
    assert tracker.get_stats()["total_connections_seen"] == 2
    active = tracker.get_connection(second)
    assert active is not None
    active.last_seen = time.monotonic() - 301
    assert tracker.cleanup_stale() == 1
    assert tracker.get_active_count() == 0


def test_quic_initial_detection_does_not_claim_to_extract_encrypted_sni():
    initial = b"\xc0\x00\x00\x00\x01" + b"\x00" * 20
    assert QUICSNIExtractor.is_quic_initial(initial)
    assert QUICSNIExtractor.extract(initial) is None
    v2_initial = b"\xd0\x6b\x33\x43\xcf" + b"\x00" * 20
    assert QUICSNIExtractor.is_quic_initial(v2_initial)
    hello = tls_client_hello("example.com")
    assert QUICSNIExtractor.extract(initial + hello) == "example.com"


def test_thread_safe_queue_bounds_shutdown_and_drains():
    items = ThreadSafeQueue[int](max_size=1)
    assert items.try_push(1)
    assert not items.try_push(2)
    assert items.pop(timeout=0) == 1
    assert items.empty()
    assert items.push(3)
    items.shutdown()
    assert items.is_shutdown()
    assert not items.push(4)
    assert items.pop() == 3
    assert items.pop(timeout=0) is None


def test_rule_matching_persistence_and_validation(tmp_path):
    rules = RuleManager()
    rules.block_ip("192.0.2.1")
    rules.block_app(AppType.YOUTUBE)
    rules.block_domain("*.example.com")
    rules.block_domain_substring("facebook")
    rules.block_port(8443)
    assert rules.is_domain_blocked("sub.example.com")
    assert rules.is_domain_blocked("example.com")
    assert rules.is_domain_blocked("www.facebook.com")
    assert rules.should_block("192.0.2.1", 443, AppType.UNKNOWN, "") is not None
    assert rules.should_block("192.0.2.2", 8443, AppType.UNKNOWN, "") is not None
    assert rules.should_block("192.0.2.2", 443, AppType.YOUTUBE, "") is not None
    path = tmp_path / "rules.txt"
    rules.save_rules(path)
    loaded = RuleManager()
    loaded.load_rules(path)
    assert loaded.get_stats() == rules.get_stats()
    assert loaded.is_domain_blocked("example.com")
    assert loaded.is_domain_blocked("www.facebook.com")
    with pytest.raises(ValueError):
        loaded.block_ip("999.1.1.1")
    with pytest.raises(ValueError):
        loaded.block_domain("x.*.example.com")


@pytest.mark.parametrize("workers", [1, 4])
def test_end_to_end_using_existing_pcap_generator(tmp_path, workers):
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    generated = subprocess.run(
        [sys.executable, str(root / "scripts" / "generate_test_pcap.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "TLS connections with SNI" in generated.stdout
    source = tmp_path / "test_dpi.pcap"
    output = tmp_path / "filtered.pcap"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "deep_packet_analyzer",
            str(source),
            str(output),
            "--block-ip",
            "192.168.1.50",
            "--block-app",
            "YouTube",
            "--block-domain",
            "facebook",
            "--lbs",
            "1" if workers == 1 else "2",
            "--fps",
            str(workers if workers == 1 else 2),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Packets inspected: 77" in result.stdout
    assert "Dropped:           8" in result.stdout
    with PcapReader(output) as reader:
        output_packets = list(reader.packets())
    assert len(output_packets) == 69
    assert all(
        PacketParser.parse(packet).has_ip for packet in output_packets
    )


def test_packet_parse_failure_is_not_counted_as_dpi_packet(tmp_path):
    source = tmp_path / "bad-frame.pcap"
    write_pcap(source, [b"\x00" * 4, ipv4_packet(tcp_segment())])
    output = tmp_path / "filtered.pcap"
    env = os.environ.copy()
    root = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(root / "src")
    result = subprocess.run(
        [sys.executable, "-m", "deep_packet_analyzer", str(source), str(output)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Packets inspected: 1" in result.stdout
    assert "Parse errors:      1" in result.stdout


def test_inspection_cli_accepts_legacy_positional_packet_limit(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "deep_packet_analyzer",
            str(root / "samples" / "test_dpi.pcap"),
            "2",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.count("Packet #") == 2
    assert "Packets read: 2" in result.stdout


def test_checked_in_sample_captures_read_and_sample_filter_matches_report(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sample_dir = root / "samples"
    counts = {}
    for name in ("test_dpi.pcap", "output.pcap"):
        with PcapReader(sample_dir / name) as reader:
            packets = list(reader.packets())
            assert packets
            counts[name] = len(packets)
            assert all(packet.header.incl_len == len(packet.data) for packet in packets)
    assert counts["test_dpi.pcap"] == 77

    output = tmp_path / "filtered-existing-sample.pcap"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "deep_packet_analyzer",
            str(sample_dir / "test_dpi.pcap"),
            str(output),
            "--block-ip",
            "192.168.1.50",
            "--block-app",
            "YouTube",
            "--block-domain",
            "facebook",
            "--lbs",
            "2",
            "--fps",
            "2",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Packets inspected: 77" in result.stdout
    assert "Forwarded:         69" in result.stdout
    assert "Dropped:           8" in result.stdout
    with PcapReader(output) as reader:
        assert len(list(reader.packets())) == 69

"""Command-line inspection and offline PCAP filtering."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import sys

from .dpi_engine import DPIEngine, DPIEngineConfig
from .packet_parser import PacketParseError, PacketParser
from .pcap_reader import PcapFormatError, PcapReader
from .types import AppType, app_type_to_string


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deep-packet-analyzer",
        description="Inspect or filter offline classic PCAP files.",
    )
    parser.add_argument("input_pcap", help="Input classic PCAP file")
    parser.add_argument(
        "output_pcap",
        nargs="?",
        help="Filtered output PCAP; omit to inspect packets without writing output",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Print packet summaries (also the default when output_pcap is omitted)",
    )
    parser.add_argument("--max-packets", type=_positive_int)
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP")
    parser.add_argument(
        "--block-domain", action="append", default=[], metavar="DOMAIN"
    )
    parser.add_argument("--block-port", action="append", type=int, default=[], metavar="PORT")
    parser.add_argument("--rules", help="Load rules from a rules file")
    parser.add_argument("--lbs", type=_positive_int, default=2)
    parser.add_argument("--fps", type=_positive_int, default=2)
    parser.add_argument("--queue-size", type=_positive_int, default=1000)
    parser.add_argument("--verbose", action="store_true")
    return parser


def _timestamp_text(reader: PcapReader, seconds: int, fraction: int) -> str:
    assert reader.global_header is not None
    fractional_digits = 6 if reader.global_header.timestamp_resolution == 1_000_000 else 9
    timestamp = datetime.fromtimestamp(seconds, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    return f"{timestamp}.{fraction:0{fractional_digits}d}+00:00"


def _inspect_file(input_pcap: str, max_packets: int | None) -> int:
    reader = PcapReader(input_pcap)
    header = reader.open()
    packet_count = 0
    parse_errors = 0
    try:
        if header.network != 1:
            raise PcapFormatError(
                f"Only Ethernet PCAP link type 1 is supported; got {header.network}"
            )
        while max_packets is None or packet_count < max_packets:
            raw = reader.read_packet()
            if raw is None:
                break
            packet_count += 1
            try:
                parsed = PacketParser.parse(raw)
            except PacketParseError as exc:
                parse_errors += 1
                print(f"Warning: Failed to parse packet #{packet_count}: {exc}", file=sys.stderr)
                continue
            print(
                f"Packet #{packet_count} {_timestamp_text(reader, raw.header.ts_sec, raw.header.ts_frac)} "
                f"{parsed.src_mac} -> {parsed.dest_mac} "
                f"EtherType=0x{parsed.ether_type:04x}"
            )
            if parsed.has_ip:
                protocol = PacketParser.protocol_to_string(parsed.protocol)
                print(
                    f"  IPv{parsed.ip_version} {parsed.src_ip} -> {parsed.dest_ip} "
                    f"protocol={protocol} ttl/hop-limit={parsed.ttl}"
                )
            if parsed.has_tcp or parsed.has_udp:
                transport = "TCP" if parsed.has_tcp else "UDP"
                suffix = (
                    f" flags={PacketParser.tcp_flags_to_string(parsed.tcp_flags)}"
                    if parsed.has_tcp
                    else ""
                )
                print(
                    f"  {transport} {parsed.src_port} -> {parsed.dest_port} "
                    f"payload={parsed.payload_length} bytes{suffix}"
                )
        print(f"Packets read: {packet_count}; parse errors: {parse_errors}")
    finally:
        reader.close()
    return 0


def _print_report(report: dict[str, object]) -> None:
    packets = report["packets"]
    connections = report["connections"]
    assert isinstance(packets, dict)
    assert isinstance(connections, dict)
    print("\nDPI processing report")
    print(f"  Packets inspected: {packets['total_packets']}")
    print(f"  Bytes inspected:   {packets['total_bytes']}")
    print(f"  TCP / UDP:         {packets['tcp_packets']} / {packets['udp_packets']}")
    print(f"  Parse errors:      {packets['parse_errors']}")
    print(f"  Forwarded:         {packets['forwarded_packets']}")
    print(f"  Dropped:           {packets['dropped_packets']}")
    print(f"  Active flows:      {connections['total_active_connections']}")
    print("  Application counts:")
    app_counts = packets["app_counts"]
    assert isinstance(app_counts, dict)
    for app, count in sorted(
        app_counts.items(), key=lambda item: (-item[1], int(item[0]))
    ):
        print(f"    {app_type_to_string(app):<12} {count}")
    top_domains = connections["top_domains"]
    if top_domains:
        print("  Detected domains:")
        for domain, count in top_domains:
            print(f"    {domain}: {count} flow(s)")
    print("  Worker packets:")
    for worker in report["workers"]:
        print(
            f"    FP{worker['id']}: {worker['processed']} processed, "
            f"{worker['dropped']} dropped"
        )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.max_packets is None and args.output_pcap is not None:
        try:
            legacy_limit = int(args.output_pcap)
        except ValueError:
            pass
        else:
            args.output_pcap = None
            args.max_packets = legacy_limit if legacy_limit > 0 else None
    if args.inspect and args.output_pcap:
        parser.error("--inspect cannot be combined with output_pcap")
    if args.output_pcap is None:
        return _inspect_file(args.input_pcap, args.max_packets)
    try:
        engine = DPIEngine(
            DPIEngineConfig(
                num_load_balancers=args.lbs,
                fps_per_lb=args.fps,
                queue_size=args.queue_size,
                rules_file=args.rules or "",
                verbose=args.verbose,
            )
        )
        for ip in args.block_ip:
            engine.block_ip(str(ipaddress.ip_address(ip)))
        for app in args.block_app:
            engine.block_app(AppType[app.upper()] if app.upper() in AppType.__members__ else app)
        for domain in args.block_domain:
            if domain.startswith("*."):
                engine.block_domain(domain)
            else:
                engine.block_domain_substring(domain)
        for port in args.block_port:
            engine.block_port(port)
        report = engine.process_file(
            args.input_pcap, args.output_pcap, max_packets=args.max_packets
        )
        _print_report(report)
    except (OSError, PcapFormatError, PacketParseError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0

"""Per-worker flow inspection, classification, and rule decisions."""

from __future__ import annotations

from dataclasses import dataclass

from .connection_tracker import ConnectionTracker
from .packet_parser import ParsedPacket
from .pcap_reader import RawPacket
from .rule_manager import RuleManager
from .sni_extractor import extract_dns_query, extract_http_host, extract_sni
from .types import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
    PacketJob,
    sni_to_app_type,
)


@dataclass(slots=True)
class FastPathStats:
    packets_processed: int = 0
    packets_forwarded: int = 0
    packets_dropped: int = 0
    sni_extractions: int = 0
    classification_hits: int = 0


class FastPathProcessor:
    def __init__(
        self,
        fp_id: int,
        rule_manager: RuleManager,
        max_connections: int = 100_000,
    ) -> None:
        self.fp_id = fp_id
        self.rule_manager = rule_manager
        self.connection_tracker = ConnectionTracker(fp_id, max_connections)
        self.stats = FastPathStats()

    def process_packet(self, job: PacketJob) -> PacketAction:
        raw = job.raw_packet
        parsed = job.parsed_packet
        if not isinstance(raw, RawPacket) or not isinstance(parsed, ParsedPacket):
            raise TypeError("PacketJob must contain RawPacket and ParsedPacket values")
        connection = self.connection_tracker.get_or_create_connection(job.tuple)
        self.connection_tracker.update_connection(connection, len(raw.data))
        self.stats.packets_processed += 1
        if parsed.has_tcp:
            self._update_tcp_state(connection, parsed.tcp_flags)
        if connection.blocked:
            self.stats.packets_dropped += 1
            return PacketAction.DROP

        payload = raw.data[
            parsed.payload_offset : parsed.payload_offset + parsed.payload_length
        ]
        if payload and connection.state != ConnectionState.CLASSIFIED:
            self._inspect_payload(job.tuple, parsed, payload, connection)

        reason = self.rule_manager.should_block(
            job.tuple.src_ip,
            job.tuple.dst_port,
            connection.app_type,
            connection.sni,
        )
        if reason is not None:
            self.connection_tracker.block_connection(connection)
            self.stats.packets_dropped += 1
            return PacketAction.DROP
        self.stats.packets_forwarded += 1
        return PacketAction.FORWARD

    def _inspect_payload(
        self,
        flow: FiveTuple,
        parsed: ParsedPacket,
        payload: bytes,
        connection: Connection,
    ) -> None:
        if parsed.has_tcp and flow.dst_port == 443:
            sni = extract_sni(payload)
            if sni:
                self.stats.sni_extractions += 1
                app = sni_to_app_type(sni)
                self.connection_tracker.classify_connection(connection, app, sni)
                if app not in {AppType.UNKNOWN, AppType.HTTPS}:
                    self.stats.classification_hits += 1
                return
            if connection.app_type == AppType.UNKNOWN:
                connection.app_type = AppType.HTTPS
        elif parsed.has_tcp and flow.dst_port == 80:
            host = extract_http_host(payload)
            if host:
                app = sni_to_app_type(host)
                self.connection_tracker.classify_connection(connection, app, host)
                if app not in {AppType.UNKNOWN, AppType.HTTP}:
                    self.stats.classification_hits += 1
                return
            if connection.app_type == AppType.UNKNOWN:
                connection.app_type = AppType.HTTP
        elif flow.dst_port == 53 or flow.src_port == 53:
            domain = extract_dns_query(payload)
            self.connection_tracker.classify_connection(
                connection, AppType.DNS, domain or ""
            )
            return
        if connection.app_type == AppType.UNKNOWN:
            if flow.dst_port == 443:
                connection.app_type = AppType.HTTPS
            elif flow.dst_port == 80:
                connection.app_type = AppType.HTTP

    @staticmethod
    def _update_tcp_state(connection: Connection, flags: int) -> None:
        syn, ack, fin, rst = (
            bool(flags & bit) for bit in (0x02, 0x10, 0x01, 0x04)
        )
        if syn:
            if ack:
                connection.syn_ack_seen = True
            else:
                connection.syn_seen = True
        if connection.syn_seen and connection.syn_ack_seen and ack:
            if connection.state == ConnectionState.NEW:
                connection.state = ConnectionState.ESTABLISHED
        if fin:
            connection.fin_seen = True
        if rst or (connection.fin_seen and ack):
            connection.state = ConnectionState.CLOSED

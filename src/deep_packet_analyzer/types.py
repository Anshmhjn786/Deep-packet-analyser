"""Shared packet, flow, and classification types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
import ipaddress
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from .packet_parser import ParsedPacket
    from .pcap_reader import RawPacket

IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address


class AppType(IntEnum):
    UNKNOWN = 0
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


class ConnectionState(Enum):
    NEW = "new"
    ESTABLISHED = "established"
    CLASSIFIED = "classified"
    BLOCKED = "blocked"
    CLOSED = "closed"


class PacketAction(Enum):
    FORWARD = "forward"
    DROP = "drop"
    INSPECT = "inspect"
    LOG_ONLY = "log_only"


APP_LABELS = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    return APP_LABELS.get(app, "Unknown")


def app_type_from_string(value: str) -> AppType:
    normalized = value.strip().casefold()
    for app, label in APP_LABELS.items():
        if normalized in {label.casefold(), app.name.casefold()}:
            return app
    raise ValueError(f"Unknown application type: {value!r}")


def sni_to_app_type(sni: str) -> AppType:
    """Map a hostname to the legacy C++ application's substring signatures."""
    if not sni:
        return AppType.UNKNOWN
    domain = sni.casefold()
    patterns = (
        (AppType.GOOGLE, ("google", "gstatic", "googleapis", "ggpht", "gvt1")),
        (AppType.YOUTUBE, ("youtube", "ytimg", "youtu.be", "yt3.ggpht")),
        (AppType.FACEBOOK, ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")),
        (AppType.INSTAGRAM, ("instagram", "cdninstagram")),
        (AppType.WHATSAPP, ("whatsapp", "wa.me")),
        (AppType.TWITTER, ("twitter", "twimg", "x.com", "t.co")),
        (AppType.NETFLIX, ("netflix", "nflxvideo", "nflximg")),
        (AppType.AMAZON, ("amazon", "amazonaws", "cloudfront", "aws")),
        (
            AppType.MICROSOFT,
            ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
        ),
        (AppType.APPLE, ("apple", "icloud", "mzstatic", "itunes")),
        (AppType.TELEGRAM, ("telegram", "t.me")),
        (AppType.TIKTOK, ("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
        (AppType.SPOTIFY, ("spotify", "scdn.co")),
        (AppType.ZOOM, ("zoom",)),
        (AppType.DISCORD, ("discord", "discordapp")),
        (AppType.GITHUB, ("github", "githubusercontent")),
        (AppType.CLOUDFLARE, ("cloudflare", "cf-")),
    )
    for app, signatures in patterns:
        if any(signature in domain for signature in signatures):
            return app
    return AppType.HTTPS


@dataclass(frozen=True, slots=True)
class FiveTuple:
    src_ip: IPAddress
    dst_ip: IPAddress
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> FiveTuple:
        return FiveTuple(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol
        )

    def __str__(self) -> str:
        protocol = {6: "TCP", 17: "UDP"}.get(self.protocol, "?")
        return (
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} ({protocol})"
        )


@dataclass(slots=True)
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    action: PacketAction = PacketAction.FORWARD
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False
    blocked: bool = False


@dataclass(slots=True)
class PacketJob:
    packet_id: int
    raw_packet: RawPacket
    parsed_packet: ParsedPacket
    tuple: FiveTuple
    tcp_flags: int = 0


@dataclass(slots=True)
class DPIStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    parse_errors: int = 0
    app_counts: dict[AppType, int] = field(default_factory=dict)

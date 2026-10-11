"""Streaming reader and writer for classic PCAP files."""

from __future__ import annotations

from dataclasses import dataclass
import os
import struct
from typing import BinaryIO, Iterator

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_MAX_CAPTURED_PACKET = 16 * 1024 * 1024


class PcapFormatError(ValueError):
    """A malformed, unsupported, or truncated classic PCAP stream."""


@dataclass(frozen=True, slots=True)
class PcapGlobalHeader:
    raw: bytes
    byte_order: str
    timestamp_resolution: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass(frozen=True, slots=True)
class PcapPacketHeader:
    ts_sec: int
    ts_frac: int
    incl_len: int
    orig_len: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class RawPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self, filename: str | os.PathLike[str]) -> None:
        self.filename = os.fspath(filename)
        self._file: BinaryIO | None = None
        self.global_header: PcapGlobalHeader | None = None

    def open(self) -> PcapGlobalHeader:
        self.close()
        stream = open(self.filename, "rb")
        raw = stream.read(24)
        if len(raw) != 24:
            stream.close()
            raise PcapFormatError("PCAP global header is truncated")
        byte_order_info = _MAGIC.get(raw[:4])
        if byte_order_info is None:
            stream.close()
            raise PcapFormatError(f"Unsupported PCAP magic number {raw[:4].hex()}")
        byte_order, resolution = byte_order_info
        major, minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            byte_order + "HHiIII", raw[4:]
        )
        if major != 2:
            stream.close()
            raise PcapFormatError(f"Unsupported PCAP version {major}.{minor}")
        if snaplen == 0:
            stream.close()
            raise PcapFormatError("PCAP snaplen must be greater than zero")
        self._file = stream
        self.global_header = PcapGlobalHeader(
            raw,
            byte_order,
            resolution,
            major,
            minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        )
        return self.global_header

    def read_packet(self) -> RawPacket | None:
        if self._file is None or self.global_header is None:
            raise RuntimeError("PCAP reader is not open")
        packet_header_raw = self._file.read(16)
        if not packet_header_raw:
            return None
        if len(packet_header_raw) != 16:
            raise PcapFormatError("PCAP packet header is truncated")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            self.global_header.byte_order + "IIII", packet_header_raw
        )
        if ts_frac >= self.global_header.timestamp_resolution:
            raise PcapFormatError(
                f"Invalid timestamp fraction {ts_frac} for this PCAP precision"
            )
        if orig_len < incl_len:
            raise PcapFormatError(
                f"Original packet length {orig_len} is smaller than captured length {incl_len}"
            )
        if incl_len > self.global_header.snaplen or incl_len > _MAX_CAPTURED_PACKET:
            raise PcapFormatError(
                f"Invalid captured packet length {incl_len} "
                f"(snaplen {self.global_header.snaplen})"
            )
        data = self._file.read(incl_len)
        if len(data) != incl_len:
            raise PcapFormatError(
                f"Packet data is truncated: expected {incl_len} bytes, got {len(data)}"
            )
        return RawPacket(
            PcapPacketHeader(ts_sec, ts_frac, incl_len, orig_len, packet_header_raw),
            data,
        )

    def packets(self) -> Iterator[RawPacket]:
        while (packet := self.read_packet()) is not None:
            yield packet

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
        self._file = None
        self.global_header = None

    def __enter__(self) -> PcapReader:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class PcapWriter:
    def __init__(
        self, filename: str | os.PathLike[str], header: PcapGlobalHeader
    ) -> None:
        self.filename = os.fspath(filename)
        self._file = open(self.filename, "wb")
        self._file.write(header.raw)
        self._byte_order = header.byte_order

    def write_packet(self, packet: RawPacket) -> None:
        self._file.write(packet.header.raw)
        self._file.write(packet.data)

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

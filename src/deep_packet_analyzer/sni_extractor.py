"""Bounded TLS ClientHello, HTTP Host, and DNS query inspection."""

from __future__ import annotations

import struct

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SNI_EXTENSION = 0x0000


def is_tls_client_hello(payload: bytes) -> bool:
    if len(payload) < 9 or payload[0] != TLS_HANDSHAKE:
        return False
    version = struct.unpack_from("!H", payload, 1)[0]
    record_length = struct.unpack_from("!H", payload, 3)[0]
    return (
        0x0300 <= version <= 0x0304
        and record_length >= 4
        and record_length <= len(payload) - 5
        and payload[5] == TLS_CLIENT_HELLO
    )


def _client_hello_extensions(payload: bytes) -> tuple[int, int] | None:
    if not is_tls_client_hello(payload):
        return None
    record_end = 5 + struct.unpack_from("!H", payload, 3)[0]
    handshake_length = int.from_bytes(payload[6:9], "big")
    handshake_end = min(record_end, 9 + handshake_length)
    offset = 9
    if offset + 34 > handshake_end:
        return None
    offset += 34
    if offset >= handshake_end:
        return None
    session_id_length = payload[offset]
    offset += 1
    if offset + session_id_length + 2 > handshake_end:
        return None
    offset += session_id_length
    cipher_suites_length = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    if cipher_suites_length % 2 or offset + cipher_suites_length + 1 > handshake_end:
        return None
    offset += cipher_suites_length
    compression_length = payload[offset]
    offset += 1
    if offset + compression_length + 2 > handshake_end:
        return None
    offset += compression_length
    extensions_length = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    extensions_end = offset + extensions_length
    if extensions_end > handshake_end:
        return None
    return offset, extensions_end


def extract_extensions(payload: bytes) -> list[tuple[int, bytes]]:
    bounds = _client_hello_extensions(payload)
    if bounds is None:
        return []
    offset, extensions_end = bounds
    extensions: list[tuple[int, bytes]] = []
    while offset < extensions_end:
        if offset + 4 > extensions_end:
            return []
        extension_type, extension_length = struct.unpack_from("!HH", payload, offset)
        offset += 4
        end = offset + extension_length
        if end > extensions_end:
            return []
        extensions.append((extension_type, payload[offset:end]))
        offset = end
    return extensions


def extract_sni(payload: bytes) -> str | None:
    for extension_type, extension in extract_extensions(payload):
        if extension_type != TLS_SNI_EXTENSION:
            continue
        if len(extension) < 2:
            return None
        list_length = struct.unpack_from("!H", extension)[0]
        if list_length != len(extension) - 2:
            return None
        offset = 2
        while offset < len(extension):
            if offset + 3 > len(extension):
                return None
            name_type = extension[offset]
            name_length = struct.unpack_from("!H", extension, offset + 1)[0]
            offset += 3
            end = offset + name_length
            if end > len(extension):
                return None
            if name_type == 0:
                try:
                    hostname = extension[offset:end].decode("ascii")
                except UnicodeDecodeError:
                    return None
                return hostname or None
            offset = end
        return None
    return None


def is_http_request(payload: bytes) -> bool:
    first_line = payload.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    methods = {b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"PATCH", b"OPTIONS"}
    return (
        len(parts) == 3
        and parts[0] in methods
        and parts[2].startswith(b"HTTP/")
    )


def extract_http_host(payload: bytes) -> str | None:
    if not is_http_request(payload):
        return None
    header_block = payload.split(b"\r\n\r\n", 1)[0]
    for line in header_block.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"host":
            host = value.strip().decode("latin-1").rstrip(".")
            if host.startswith("[") and "]" in host:
                return host[1 : host.index("]")]
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return None


def is_dns_query(payload: bytes) -> bool:
    return (
        len(payload) >= 12
        and not (payload[2] & 0x80)
        and struct.unpack_from("!H", payload, 4)[0] > 0
    )


def extract_dns_query(payload: bytes) -> str | None:
    if not is_dns_query(payload):
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            return ".".join(labels) or None
        if length & 0xC0 or length > 63 or offset + length > len(payload):
            return None
        label = payload[offset : offset + length]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += length
    return None


def is_quic_initial(payload: bytes) -> bool:
    if len(payload) < 7 or not payload[0] & 0x80:
        return False
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return False
    packet_type = payload[0] & 0x30
    if version == 0x6B3343CF:  # QUIC v2 uses a different long-header type mapping.
        return packet_type == 0x10
    return packet_type == 0x00


def extract_quic_sni(payload: bytes) -> str | None:
    """Find a contiguous plaintext ClientHello in a detected QUIC Initial payload."""
    if not is_quic_initial(payload):
        return None
    for offset, content_type in enumerate(payload[:-8]):
        if content_type == TLS_HANDSHAKE:
            hostname = extract_sni(payload[offset:])
            if hostname:
                return hostname
    return None


class SNIExtractor:
    extract = staticmethod(extract_sni)
    is_tls_client_hello = staticmethod(is_tls_client_hello)
    extract_extensions = staticmethod(extract_extensions)


class HTTPHostExtractor:
    extract = staticmethod(extract_http_host)
    is_http_request = staticmethod(is_http_request)


class DNSExtractor:
    extract_query = staticmethod(extract_dns_query)
    is_dns_query = staticmethod(is_dns_query)


class QUICSNIExtractor:
    is_quic_initial = staticmethod(is_quic_initial)
    extract = staticmethod(extract_quic_sni)

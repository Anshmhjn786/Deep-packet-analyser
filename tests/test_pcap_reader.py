import struct

import pytest

from deep_packet_analyzer.pcap_reader import PcapFormatError, PcapReader, PcapWriter

from helpers import raw_packet, write_pcap


def test_reads_packets_and_preserves_headers(tmp_path):
    path = tmp_path / "sample.pcap"
    frame = b"\x00" * 14
    write_pcap(path, [frame, frame + b"x"])
    reader = PcapReader(path)
    header = reader.open()
    assert (header.version_major, header.version_minor, header.network) == (2, 4, 1)
    packets = list(reader.packets())
    assert [packet.data for packet in packets] == [frame, frame + b"x"]
    reader.close()
    output = tmp_path / "copy.pcap"
    with PcapWriter(output, header) as writer:
        for packet in packets:
            writer.write_packet(packet)
    assert output.read_bytes() == path.read_bytes()


def test_reads_empty_pcap(tmp_path):
    path = tmp_path / "empty.pcap"
    write_pcap(path, [])
    with PcapReader(path) as reader:
        assert list(reader.packets()) == []


@pytest.mark.parametrize(
    ("magic", "byte_order", "resolution"),
    [
        (b"\xa1\xb2\xc3\xd4", ">", 1_000_000),
        (b"\x4d\x3c\xb2\xa1", "<", 1_000_000_000),
    ],
)
def test_reads_byte_order_and_timestamp_precision(
    tmp_path, magic, byte_order, resolution
):
    path = tmp_path / f"precision-{resolution}.pcap"
    frame = b"\x00" * 14
    global_header = magic + struct.pack(
        byte_order + "HHiIII", 2, 4, 0, 0, 65535, 1
    )
    packet_header = struct.pack(
        byte_order + "IIII", 7, resolution - 1, len(frame), len(frame)
    )
    path.write_bytes(global_header + packet_header + frame)
    with PcapReader(path) as reader:
        assert reader.global_header.timestamp_resolution == resolution
        packet = reader.read_packet()
        assert packet.header.ts_sec == 7
        assert packet.header.ts_frac == resolution - 1
        assert reader.read_packet() is None


def test_rejects_truncated_global_and_record_headers(tmp_path):
    global_path = tmp_path / "global.pcap"
    global_path.write_bytes(b"\xd4\xc3")
    with pytest.raises(PcapFormatError, match="global header"):
        PcapReader(global_path).open()

    record_path = tmp_path / "record.pcap"
    write_pcap(record_path, [])
    record_path.write_bytes(record_path.read_bytes() + b"\x00" * 8)
    reader = PcapReader(record_path)
    reader.open()
    with pytest.raises(PcapFormatError, match="packet header"):
        reader.read_packet()


def test_rejects_truncated_packet_payload_and_oversized_length(tmp_path):
    truncated = tmp_path / "truncated.pcap"
    write_pcap(truncated, [])
    truncated.write_bytes(
        truncated.read_bytes() + struct.pack("<IIII", 1, 0, 8, 8) + b"abc"
    )
    reader = PcapReader(truncated)
    reader.open()
    with pytest.raises(PcapFormatError, match="Packet data"):
        reader.read_packet()

    oversized = tmp_path / "oversized.pcap"
    write_pcap(oversized, [])
    oversized.write_bytes(
        oversized.read_bytes() + struct.pack("<IIII", 1, 0, 65536, 65536)
    )
    reader = PcapReader(oversized)
    reader.open()
    with pytest.raises(PcapFormatError, match="Invalid captured"):
        reader.read_packet()

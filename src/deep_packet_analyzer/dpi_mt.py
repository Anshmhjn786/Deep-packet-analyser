"""Bounded threaded dispatch and ordered PCAP output."""

from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import ipaddress
from typing import Callable
from pathlib import Path

from .packet_parser import PacketParseError, PacketParser
from .pcap_reader import PcapFormatError, PcapReader, PcapWriter
from .thread_safe_queue import ThreadSafeQueue
from .types import AppType, DPIStats, FiveTuple, PacketAction, PacketJob


@dataclass(slots=True)
class _Result:
    packet_id: int
    job: PacketJob
    action: PacketAction | None
    error: Exception | None = None


def process_pcap_concurrently(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    worker_count: int,
    queue_size: int,
    route: Callable[[FiveTuple], int],
    process_job: Callable[[int, PacketJob], PacketAction],
    stats: DPIStats,
    stats_lock: threading.Lock,
    max_packets: int | None = None,
    verbose: bool = False,
) -> None:
    if worker_count <= 0 or queue_size <= 0:
        raise ValueError("worker_count and queue_size must be positive")
    if max_packets is not None and max_packets <= 0:
        raise ValueError("max_packets must be positive")
    if Path(input_path).resolve() == Path(output_path).resolve():
        raise ValueError("Input and output PCAP paths must be different")

    reader = PcapReader(input_path)
    header = reader.open()
    if header.network != 1:
        reader.close()
        raise PcapFormatError(
            f"Only Ethernet PCAP link type 1 is supported; got {header.network}"
        )
    try:
        writer = PcapWriter(output_path, header)
    except OSError:
        reader.close()
        raise

    jobs: list[ThreadSafeQueue[PacketJob]] = [
        ThreadSafeQueue(max_size=queue_size) for _ in range(worker_count)
    ]
    results: ThreadSafeQueue[_Result | object] = ThreadSafeQueue(
        max_size=max(1, queue_size * worker_count)
    )
    worker_finished = object()
    worker_errors: list[Exception] = []
    writer_errors: list[Exception] = []
    error_lock = threading.Lock()
    accepted_packets = 0
    pending: dict[int, _Result] = {}
    next_packet_id = 0

    def worker_loop(worker_id: int) -> None:
        while True:
            job = jobs[worker_id].pop()
            if job is None:
                results.push(worker_finished)
                return
            try:
                action = process_job(worker_id, job)
                results.push(_Result(job.packet_id, job, action))
            except Exception as exc:
                with error_lock:
                    worker_errors.append(exc)
                results.push(_Result(job.packet_id, job, None, exc))

    def write_in_order(result: _Result) -> None:
        nonlocal next_packet_id
        pending[result.packet_id] = result
        while next_packet_id in pending:
            ready = pending.pop(next_packet_id)
            if ready.error is None and ready.action == PacketAction.FORWARD:
                try:
                    writer.write_packet(ready.job.raw_packet)
                except Exception as exc:
                    with error_lock:
                        writer_errors.append(exc)
            next_packet_id += 1

    workers = [
        threading.Thread(target=worker_loop, args=(worker_id,), daemon=True)
        for worker_id in range(worker_count)
    ]
    for thread in workers:
        thread.start()

    def output_loop() -> None:
        finished_workers = 0
        while finished_workers < worker_count:
            result = results.pop()
            if result is worker_finished:
                finished_workers += 1
            elif isinstance(result, _Result):
                write_in_order(result)
            else:
                raise RuntimeError("Result queue shut down before workers completed")

    output_thread = threading.Thread(target=output_loop, daemon=True)
    output_thread.start()
    producer_error: Exception | None = None
    raw_packet_count = 0
    try:
        while max_packets is None or raw_packet_count < max_packets:
            raw = reader.read_packet()
            if raw is None:
                break
            raw_packet_count += 1
            try:
                parsed = PacketParser.parse(raw)
            except PacketParseError as exc:
                with stats_lock:
                    stats.parse_errors += 1
                if verbose:
                    print(f"Warning: Skipping malformed packet #{raw_packet_count}: {exc}")
                continue
            if not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
                continue
            flow = FiveTuple(
                ipaddress.ip_address(parsed.src_ip),
                ipaddress.ip_address(parsed.dest_ip),
                parsed.src_port,
                parsed.dest_port,
                parsed.protocol,
            )
            job = PacketJob(accepted_packets, raw, parsed, flow, parsed.tcp_flags)
            accepted_packets += 1
            with stats_lock:
                stats.total_packets += 1
                stats.total_bytes += len(raw.data)
                if parsed.has_tcp:
                    stats.tcp_packets += 1
                elif parsed.has_udp:
                    stats.udp_packets += 1
            worker_id = route(flow)
            if not 0 <= worker_id < worker_count:
                raise ValueError(f"Router returned invalid worker id {worker_id}")
            if not jobs[worker_id].push(job):
                raise RuntimeError(f"Worker queue {worker_id} shut down during dispatch")
    except Exception as exc:
        producer_error = exc
    finally:
        reader.close()
        for worker_queue in jobs:
            worker_queue.shutdown()

    for thread in workers:
        thread.join()
    output_thread.join()
    writer.close()
    if pending or next_packet_id != accepted_packets:
        raise RuntimeError(
            f"Concurrent pipeline lost results: expected {accepted_packets}, "
            f"ordered {next_packet_id}, pending {len(pending)}"
        )
    if writer_errors:
        raise OSError("Failed writing output PCAP") from writer_errors[0]
    if worker_errors:
        raise RuntimeError("Packet worker failed") from worker_errors[0]
    if producer_error:
        raise producer_error
    if verbose:
        print(
            f"Processed {accepted_packets} TCP/UDP packets from "
            f"{raw_packet_count} PCAP records"
        )

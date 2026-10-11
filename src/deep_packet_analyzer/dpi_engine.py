"""Offline DPI orchestration and aggregate packet statistics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import threading

from .connection_tracker import GlobalConnectionTable
from .fast_path import FastPathProcessor
from .load_balancer import LoadBalancerManager
from .rule_manager import RuleManager
from .types import AppType, DPIStats, PacketAction, PacketJob


@dataclass(frozen=True, slots=True)
class DPIEngineConfig:
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    queue_size: int = 1000
    max_connections: int = 100_000
    rules_file: str = ""
    verbose: bool = False

    def __post_init__(self) -> None:
        if self.num_load_balancers <= 0 or self.fps_per_lb <= 0:
            raise ValueError("Load balancer and fast-path counts must be positive")
        if self.queue_size <= 0 or self.max_connections <= 0:
            raise ValueError("Queue and connection limits must be positive")


class DPIEngine:
    def __init__(self, config: DPIEngineConfig | None = None) -> None:
        self.config = config or DPIEngineConfig()
        self.rule_manager = RuleManager()
        if self.config.rules_file:
            self.rule_manager.load_rules(self.config.rules_file)
        self.load_balancer = LoadBalancerManager(
            self.config.num_load_balancers, self.config.fps_per_lb
        )
        self.fast_paths = [
            FastPathProcessor(
                worker_id, self.rule_manager, self.config.max_connections
            )
            for worker_id in range(self.load_balancer.worker_count)
        ]
        self.global_connection_table = GlobalConnectionTable(
            [fast_path.connection_tracker for fast_path in self.fast_paths]
        )
        self.stats = DPIStats()
        self._stats_lock = threading.Lock()
        self._running = False

    def block_ip(self, ip: str) -> None:
        self.rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        self.rule_manager.unblock_ip(ip)

    def block_app(self, app: AppType | str) -> None:
        self.rule_manager.block_app(app)

    def unblock_app(self, app: AppType | str) -> None:
        self.rule_manager.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        self.rule_manager.block_domain(domain)

    def block_domain_substring(self, domain: str) -> None:
        self.rule_manager.block_domain_substring(domain)

    def unblock_domain(self, domain: str) -> None:
        self.rule_manager.unblock_domain(domain)

    def block_port(self, port: int) -> None:
        self.rule_manager.block_port(port)

    def unblock_port(self, port: int) -> None:
        self.rule_manager.unblock_port(port)

    def load_rules(self, filename: str) -> None:
        self.rule_manager.load_rules(filename)

    def save_rules(self, filename: str) -> None:
        self.rule_manager.save_rules(filename)

    def process_file(
        self, input_file: str, output_file: str, max_packets: int | None = None
    ) -> dict[str, object]:
        from .dpi_mt import process_pcap_concurrently

        if self._running:
            raise RuntimeError("DPI engine is already processing a file")
        self._running = True
        try:
            process_pcap_concurrently(
                input_file,
                output_file,
                worker_count=self.load_balancer.worker_count,
                queue_size=self.config.queue_size,
                route=self.load_balancer.select_worker,
                process_job=self._process_job,
                stats=self.stats,
                stats_lock=self._stats_lock,
                max_packets=max_packets,
                verbose=self.config.verbose,
            )
        finally:
            self._running = False
        return self.get_report()

    @property
    def is_running(self) -> bool:
        return self._running

    def _process_job(self, worker_id: int, job: PacketJob) -> PacketAction:
        action = self.fast_paths[worker_id].process_packet(job)
        connection = self.fast_paths[worker_id].connection_tracker.get_connection(
            job.tuple
        )
        if connection is None:
            raise RuntimeError("Processed packet flow was not added to its tracker")
        with self._stats_lock:
            app = connection.app_type
            self.stats.app_counts[app] = self.stats.app_counts.get(app, 0) + 1
            if action == PacketAction.DROP:
                self.stats.dropped_packets += 1
            else:
                self.stats.forwarded_packets += 1
        return action

    def get_report(self) -> dict[str, object]:
        with self._stats_lock:
            packet_stats = asdict(self.stats)
        connection_stats = self.global_connection_table.get_global_stats()
        return {
            "packets": packet_stats,
            "connections": connection_stats,
            "rules": self.rule_manager.get_stats(),
            "workers": [
                {
                    "id": fast_path.fp_id,
                    "processed": fast_path.stats.packets_processed,
                    "forwarded": fast_path.stats.packets_forwarded,
                    "dropped": fast_path.stats.packets_dropped,
                    "active_connections": fast_path.connection_tracker.get_active_count(),
                }
                for fast_path in self.fast_paths
            ],
        }

    def generate_classification_report(self) -> str:
        report = self.get_report()
        connections = report["connections"]
        distribution = connections["app_distribution"]
        total = sum(distribution.values())
        lines = [
            f"Total connections: {total}",
            f"Classified: {total - distribution.get(AppType.UNKNOWN, 0)}",
            f"Unidentified: {distribution.get(AppType.UNKNOWN, 0)}",
            "Application distribution:",
        ]
        for app, count in sorted(
            distribution.items(), key=lambda item: (-item[1], int(item[0]))
        ):
            lines.append(f"  {app.name}: {count}")
        return "\n".join(lines)

    def generate_report(self) -> str:
        report = self.get_report()
        packets = report["packets"]
        connections = report["connections"]
        lines = [
            "DPI engine statistics",
            f"Total packets: {packets['total_packets']}",
            f"Total bytes: {packets['total_bytes']}",
            f"TCP packets: {packets['tcp_packets']}",
            f"UDP packets: {packets['udp_packets']}",
            f"Forwarded: {packets['forwarded_packets']}",
            f"Dropped: {packets['dropped_packets']}",
            f"Active connections: {connections['total_active_connections']}",
            "Rules: "
            + ", ".join(
                f"{name}={count}" for name, count in report["rules"].items()
            ),
        ]
        for worker in report["workers"]:
            lines.append(
                f"FP{worker['id']}: processed={worker['processed']} "
                f"forwarded={worker['forwarded']} dropped={worker['dropped']}"
            )
        return "\n".join(lines)

    def print_status(self) -> None:
        report = self.get_report()
        packets = report["packets"]
        connections = report["connections"]
        print(
            f"Packets: {packets['total_packets']} | "
            f"Forwarded: {packets['forwarded_packets']} | "
            f"Dropped: {packets['dropped_packets']} | "
            f"Connections: {connections['total_active_connections']}"
        )

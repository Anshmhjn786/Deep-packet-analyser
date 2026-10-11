"""Bounded flow tracking and aggregate connection reporting."""

from __future__ import annotations

from collections import OrderedDict, Counter
import threading
import time
from typing import Callable

from .types import AppType, Connection, ConnectionState, FiveTuple, PacketAction


class ConnectionTracker:
    def __init__(self, fp_id: int = 0, max_connections: int = 100_000) -> None:
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        self.fp_id = fp_id
        self.max_connections = max_connections
        self._connections: OrderedDict[FiveTuple, Connection] = OrderedDict()
        self._lock = threading.RLock()
        self.total_connections_seen = 0
        self.classified_connections = 0
        self.blocked_connections = 0

    def get_or_create_connection(self, flow: FiveTuple) -> Connection:
        now = time.monotonic()
        with self._lock:
            connection = self._connections.get(flow)
            if connection is not None:
                connection.last_seen = now
                self._connections.move_to_end(flow)
                return connection
            if len(self._connections) >= self.max_connections:
                self._connections.popitem(last=False)
            connection = Connection(flow, first_seen=now, last_seen=now)
            self._connections[flow] = connection
            self.total_connections_seen += 1
            return connection

    def get_connection(self, flow: FiveTuple) -> Connection | None:
        with self._lock:
            return self._connections.get(flow) or self._connections.get(flow.reverse())

    def update_connection(
        self, connection: Connection, packet_size: int, is_outbound: bool = True
    ) -> None:
        now = time.monotonic()
        with self._lock:
            connection.last_seen = now
            if is_outbound:
                connection.packets_out += 1
                connection.bytes_out += packet_size
            else:
                connection.packets_in += 1
                connection.bytes_in += packet_size

    def classify_connection(
        self, connection: Connection, app: AppType, sni: str = ""
    ) -> None:
        with self._lock:
            if connection.state != ConnectionState.CLASSIFIED:
                connection.app_type = app
                connection.sni = sni
                connection.state = ConnectionState.CLASSIFIED
                self.classified_connections += 1

    def block_connection(self, connection: Connection) -> None:
        with self._lock:
            if not connection.blocked:
                self.blocked_connections += 1
            connection.blocked = True
            connection.state = ConnectionState.BLOCKED
            connection.action = PacketAction.DROP

    def close_connection(self, flow: FiveTuple) -> None:
        with self._lock:
            connection = self._connections.get(flow)
            if connection is not None:
                connection.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout: float = 300.0) -> int:
        if timeout < 0:
            raise ValueError("timeout cannot be negative")
        now = time.monotonic()
        with self._lock:
            stale = [
                flow
                for flow, connection in self._connections.items()
                if connection.state == ConnectionState.CLOSED
                or now - connection.last_seen > timeout
            ]
            for flow in stale:
                del self._connections[flow]
            return len(stale)

    def get_all_connections(self) -> list[Connection]:
        with self._lock:
            return list(self._connections.values())

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._connections)

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "active_connections": len(self._connections),
                "total_connections_seen": self.total_connections_seen,
                "classified_connections": self.classified_connections,
                "blocked_connections": self.blocked_connections,
            }

    def clear(self) -> None:
        with self._lock:
            self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for connection in self.get_all_connections():
            callback(connection)


class GlobalConnectionTable:
    def __init__(self, trackers: list[ConnectionTracker] | None = None) -> None:
        self._trackers: list[ConnectionTracker | None] = list(trackers or [])
        self._lock = threading.RLock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        if fp_id < 0:
            raise ValueError("fp_id cannot be negative")
        with self._lock:
            if fp_id >= len(self._trackers):
                self._trackers.extend([None] * (fp_id + 1 - len(self._trackers)))
            self._trackers[fp_id] = tracker

    def get_global_stats(self) -> dict[str, object]:
        app_counts: Counter[AppType] = Counter()
        domain_counts: Counter[str] = Counter()
        total_active = 0
        total_seen = 0
        with self._lock:
            trackers = list(self._trackers)
        for tracker in trackers:
            if tracker is None:
                continue
            tracker_stats = tracker.get_stats()
            total_active += tracker_stats["active_connections"]
            total_seen += tracker_stats["total_connections_seen"]
            for connection in tracker.get_all_connections():
                app_counts[connection.app_type] += 1
                if connection.sni:
                    domain_counts[connection.sni] += 1
        return {
            "total_active_connections": total_active,
            "total_connections_seen": total_seen,
            "app_distribution": dict(app_counts),
            "top_domains": domain_counts.most_common(20),
        }

    def generate_report(self) -> str:
        stats = self.get_global_stats()
        lines = [
            "Connection statistics",
            f"Active connections: {stats['total_active_connections']}",
            f"Total connections seen: {stats['total_connections_seen']}",
            "Applications:",
        ]
        apps = stats["app_distribution"]
        for app, count in sorted(apps.items(), key=lambda item: (-item[1], int(item[0]))):
            lines.append(f"  {app.name}: {count}")
        if stats["top_domains"]:
            lines.append("Top domains:")
            lines.extend(f"  {domain}: {count}" for domain, count in stats["top_domains"])
        return "\n".join(lines)

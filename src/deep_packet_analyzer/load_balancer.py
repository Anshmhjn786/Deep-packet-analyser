"""Stable flow-affinity routing for the concurrent packet workers."""

from __future__ import annotations

import hashlib

from .types import FiveTuple


class LoadBalancerManager:
    def __init__(self, num_load_balancers: int = 2, fps_per_lb: int = 2) -> None:
        if num_load_balancers <= 0 or fps_per_lb <= 0:
            raise ValueError("Load balancer and worker counts must be positive")
        self.num_load_balancers = num_load_balancers
        self.fps_per_lb = fps_per_lb
        self.worker_count = num_load_balancers * fps_per_lb

    @staticmethod
    def _stable_hash(flow: FiveTuple) -> int:
        encoded = (
            f"{flow.src_ip}|{flow.dst_ip}|{flow.src_port}|"
            f"{flow.dst_port}|{flow.protocol}"
        ).encode("ascii")
        return int.from_bytes(hashlib.blake2b(encoded, digest_size=8).digest(), "big")

    def get_lb_for_packet(self, flow: FiveTuple) -> int:
        return self._stable_hash(flow) % self.num_load_balancers

    def select_worker(self, flow: FiveTuple) -> int:
        value = self._stable_hash(flow)
        lb_index = value % self.num_load_balancers
        fp_index = value % self.fps_per_lb
        return lb_index * self.fps_per_lb + fp_index

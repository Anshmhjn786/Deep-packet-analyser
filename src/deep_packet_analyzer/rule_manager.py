"""Thread-safe IP, application, domain, and destination-port rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
from pathlib import Path
import threading

from .types import AppType, app_type_from_string, app_type_to_string


class BlockType(Enum):
    IP = "IP"
    APP = "APP"
    DOMAIN = "DOMAIN"
    PORT = "PORT"


@dataclass(frozen=True, slots=True)
class BlockReason:
    type: BlockType
    detail: str


class RuleManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blocked_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: set[str] = set()
        self._domain_patterns: set[str] = set()
        self._domain_substrings: set[str] = set()
        self._blocked_ports: set[int] = set()

    @staticmethod
    def _ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address):
        return ipaddress.ip_address(value)

    def block_ip(self, value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        with self._lock:
            self._blocked_ips.add(self._ip(value))

    def unblock_ip(self, value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        with self._lock:
            self._blocked_ips.discard(self._ip(value))

    def is_ip_blocked(self, value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        with self._lock:
            return self._ip(value) in self._blocked_ips

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return sorted(map(str, self._blocked_ips))

    def block_app(self, app: AppType | str) -> None:
        with self._lock:
            self._blocked_apps.add(
                app_type_from_string(app) if isinstance(app, str) else app
            )

    def unblock_app(self, app: AppType | str) -> None:
        with self._lock:
            self._blocked_apps.discard(
                app_type_from_string(app) if isinstance(app, str) else app
            )

    def is_app_blocked(self, app: AppType) -> bool:
        with self._lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> list[AppType]:
        with self._lock:
            return sorted(self._blocked_apps, key=int)

    def block_domain(self, domain: str) -> None:
        normalized = domain.strip().rstrip(".").casefold()
        if not normalized:
            raise ValueError("Domain rule cannot be empty")
        with self._lock:
            if "*" in normalized and not normalized.startswith("*."):
                raise ValueError("Only leading *.domain wildcard rules are supported")
            if normalized.startswith("*."):
                if len(normalized) <= 2 or "*" in normalized[2:]:
                    raise ValueError(f"Invalid wildcard domain rule: {domain!r}")
                self._domain_patterns.add(normalized)
            else:
                self._blocked_domains.add(normalized)

    def block_domain_substring(self, domain: str) -> None:
        normalized = domain.strip().rstrip(".").casefold()
        if not normalized:
            raise ValueError("Domain substring rule cannot be empty")
        with self._lock:
            self._domain_substrings.add(normalized)

    def unblock_domain(self, domain: str) -> None:
        normalized = domain.strip().rstrip(".").casefold()
        with self._lock:
            self._blocked_domains.discard(normalized)
            self._domain_patterns.discard(normalized)
            self._domain_substrings.discard(normalized)

    def is_domain_blocked(self, domain: str) -> bool:
        normalized = domain.rstrip(".").casefold()
        with self._lock:
            if normalized in self._blocked_domains:
                return True
            return any(rule in normalized for rule in self._domain_substrings) or any(
                normalized == pattern[2:] or normalized.endswith(pattern[1:])
                for pattern in self._domain_patterns
            )

    def get_blocked_domains(self) -> list[str]:
        with self._lock:
            return sorted(
                self._blocked_domains
                | self._domain_patterns
                | self._domain_substrings
            )

    def block_port(self, port: int) -> None:
        self._validate_port(port)
        with self._lock:
            self._blocked_ports.add(port)

    def unblock_port(self, port: int) -> None:
        self._validate_port(port)
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._lock:
            return port in self._blocked_ports

    @staticmethod
    def _validate_port(port: int) -> None:
        if isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError(f"Invalid port: {port!r}")

    def should_block(
        self,
        src_ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
        dst_port: int,
        app: AppType,
        domain: str,
    ) -> BlockReason | None:
        address = self._ip(src_ip)
        with self._lock:
            if address in self._blocked_ips:
                return BlockReason(BlockType.IP, str(address))
            if dst_port in self._blocked_ports:
                return BlockReason(BlockType.PORT, str(dst_port))
            if app in self._blocked_apps:
                return BlockReason(BlockType.APP, app_type_to_string(app))
            normalized = domain.rstrip(".").casefold()
            if normalized and (
                normalized in self._blocked_domains
                or any(rule in normalized for rule in self._domain_substrings)
                or any(
                    normalized == pattern[2:] or normalized.endswith(pattern[1:])
                    for pattern in self._domain_patterns
                )
            ):
                return BlockReason(BlockType.DOMAIN, domain)
        return None

    def save_rules(self, filename: str | Path) -> None:
        with self._lock:
            lines = ["[BLOCKED_IPS]", *sorted(map(str, self._blocked_ips))]
            lines.extend(["", "[BLOCKED_APPS]"])
            lines.extend(app_type_to_string(app) for app in sorted(self._blocked_apps, key=int))
            lines.extend(["", "[BLOCKED_DOMAINS]", *sorted(self._blocked_domains | self._domain_patterns)])
            lines.extend(["", "[BLOCKED_DOMAIN_SUBSTRINGS]", *sorted(self._domain_substrings)])
            lines.extend(["", "[BLOCKED_PORTS]"])
            lines.extend(str(port) for port in sorted(self._blocked_ports))
        Path(filename).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def load_rules(self, filename: str | Path) -> None:
        sections: dict[str, list[str]] = {}
        current = ""
        for line_number, raw_line in enumerate(
            Path(filename).read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line
                sections.setdefault(current, [])
            elif current:
                sections[current].append(line)
            else:
                raise ValueError(f"Rule at line {line_number} has no section header")

        candidate = RuleManager()
        for value in sections.get("[BLOCKED_IPS]", []):
            candidate.block_ip(value)
        for value in sections.get("[BLOCKED_APPS]", []):
            candidate.block_app(value)
        for value in sections.get("[BLOCKED_DOMAINS]", []):
            candidate.block_domain(value)
        for value in sections.get("[BLOCKED_DOMAIN_SUBSTRINGS]", []):
            candidate.block_domain_substring(value)
        for value in sections.get("[BLOCKED_PORTS]", []):
            try:
                candidate.block_port(int(value))
            except ValueError as exc:
                raise ValueError(f"Invalid blocked port at rule value {value!r}") from exc
        with self._lock, candidate._lock:
            self._blocked_ips = candidate._blocked_ips
            self._blocked_apps = candidate._blocked_apps
            self._blocked_domains = candidate._blocked_domains
            self._domain_patterns = candidate._domain_patterns
            self._domain_substrings = candidate._domain_substrings
            self._blocked_ports = candidate._blocked_ports

    def clear_all(self) -> None:
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._domain_patterns.clear()
            self._domain_substrings.clear()
            self._blocked_ports.clear()

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "blocked_ips": len(self._blocked_ips),
                "blocked_apps": len(self._blocked_apps),
                "blocked_domains": len(
                    self._blocked_domains
                    | self._domain_patterns
                    | self._domain_substrings
                ),
                "blocked_ports": len(self._blocked_ports),
            }

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

FAILED_SSH_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
INVALID_SSH_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
ACCEPTED_SSH_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
WILDCARD_BINDS = {"*", str(ipaddress.IPv4Address(0)), str(ipaddress.IPv6Address(0))}
PROCESS_RE = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')


@dataclass(frozen=True)
class NetworkCounters:
    rx_bytes: int
    rx_errors: int
    rx_drops: int
    tx_bytes: int
    tx_errors: int
    tx_drops: int


@dataclass(frozen=True)
class Listener:
    protocol: str
    host: str
    port: int
    public_bind: bool
    process: str = ""
    pid: int | None = None


@dataclass(frozen=True)
class SocketFlow:
    local_host: str
    local_port: int
    remote_host: str
    remote_port: int
    process: str = ""
    pid: int | None = None


@dataclass(frozen=True)
class WireGuardPeer:
    interface: str
    public_key: str
    endpoint: str
    allowed_ips: tuple[str, ...]
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: int


def parse_proc_net_dev(text: str) -> dict[str, NetworkCounters]:
    values: dict[str, NetworkCounters] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        fields = raw.split()
        if len(fields) < 16:
            continue
        try:
            values[name.strip()] = NetworkCounters(
                rx_bytes=int(fields[0]),
                rx_errors=int(fields[2]),
                rx_drops=int(fields[3]),
                tx_bytes=int(fields[8]),
                tx_errors=int(fields[10]),
                tx_drops=int(fields[11]),
            )
        except ValueError:
            continue
    return values


def parse_proc_stat_cpu(text: str) -> tuple[int, int]:
    line = next((line for line in text.splitlines() if line.startswith("cpu ")), "")
    fields = line.split()[1:]
    values = [int(value) for value in fields if value.isdigit()]
    if not values:
        return 0, 0
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def cpu_percent(previous: tuple[int, int] | None, current: tuple[int, int]) -> float:
    if previous is None:
        return 0.0
    total_delta = current[0] - previous[0]
    idle_delta = current[1] - previous[1]
    if total_delta <= 0:
        return 0.0
    return round(max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)), 1)


def parse_meminfo(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        parts = raw_value.strip().split()
        if not parts:
            continue
        try:
            value = int(parts[0])
        except ValueError:
            continue
        if len(parts) > 1 and parts[1].lower() == "kb":
            value *= 1024
        values[key] = value
    return values


def memory_percent(meminfo: dict[str, int]) -> float:
    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    if total <= 0:
        return 0.0
    return round(max(0.0, min(100.0, 100.0 * (total - available) / total)), 1)


def split_endpoint(value: str) -> tuple[str, int]:
    value = value.strip().rstrip(",")
    if value.startswith("[") and "]:" in value:
        host, port_text = value[1:].rsplit("]:", 1)
    else:
        host, sep, port_text = value.rpartition(":")
        if not sep:
            return value, 0
    try:
        return host, int(port_text)
    except ValueError:
        return host, 0


def _endpoint_tokens(parts: list[str]) -> list[tuple[str, int]]:
    endpoints: list[tuple[str, int]] = []
    for token in parts:
        host, port = split_endpoint(token)
        if port > 0 and host:
            endpoints.append((host.strip("[]"), port))
            if len(endpoints) == 2:
                break
    return endpoints


def _process_from_line(line: str) -> tuple[str, int | None]:
    match = PROCESS_RE.search(line)
    if not match:
        return "", None
    return match.group("name")[:80], int(match.group("pid"))


def is_public_bind(host: str) -> bool:
    normalized = host.strip("[]")
    # This detects wildcard listener text and does not bind a socket.
    if normalized in WILDCARD_BINDS:
        return True
    try:
        ip = ipaddress.ip_address(normalized.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_private)


def parse_ss_listeners(text: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in text.splitlines():
        parts = line.split()
        endpoints = _endpoint_tokens(parts)
        if not endpoints:
            continue
        host, port = endpoints[0]
        protocol = parts[0].lower() if parts and parts[0].lower().startswith(("tcp", "udp")) else "tcp"
        process, pid = _process_from_line(line)
        listeners.append(
            Listener(
                protocol=protocol,
                host=host,
                port=port,
                public_bind=is_public_bind(host),
                process=process,
                pid=pid,
            )
        )
    return listeners


def parse_ss_connections(text: str) -> list[SocketFlow]:
    flows: list[SocketFlow] = []
    for line in text.splitlines():
        endpoints = _endpoint_tokens(line.split())
        if len(endpoints) < 2:
            continue
        process, pid = _process_from_line(line)
        flows.append(
            SocketFlow(
                local_host=endpoints[0][0],
                local_port=endpoints[0][1],
                remote_host=endpoints[1][0],
                remote_port=endpoints[1][1],
                process=process,
                pid=pid,
            )
        )
    return flows


def parse_ss_established(text: str) -> tuple[int, Counter[str], Counter[int], Counter[int]]:
    flows = parse_ss_connections(text)
    remote_ips: Counter[str] = Counter(flow.remote_host for flow in flows)
    local_ports: Counter[int] = Counter(flow.local_port for flow in flows)
    remote_ports: Counter[int] = Counter(flow.remote_port for flow in flows)
    return len(flows), remote_ips, local_ports, remote_ports


def parse_wg_dump(text: str, interface: str) -> list[WireGuardPeer]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    peers: list[WireGuardPeer] = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        try:
            handshake = int(fields[4])
            rx = int(fields[5])
            tx = int(fields[6])
            keepalive_text = fields[7].strip().lower()
            keepalive = 0 if keepalive_text in {"", "off"} else int(keepalive_text)
        except ValueError:
            continue
        peers.append(
            WireGuardPeer(
                interface=interface,
                public_key=fields[0],
                endpoint="" if fields[2] == "(none)" else fields[2],
                allowed_ips=tuple(ip.strip() for ip in fields[3].split(",") if ip.strip()),
                latest_handshake=handshake,
                transfer_rx=rx,
                transfer_tx=tx,
                persistent_keepalive=keepalive,
            )
        )
    return peers


def summarize_ssh_journal(lines: Iterable[str]) -> dict[str, object]:
    failed_by_ip: Counter[str] = Counter()
    failed_by_user: Counter[str] = Counter()
    accepted_by_ip: Counter[str] = Counter()
    accepted_by_user: Counter[str] = Counter()

    for line in lines:
        failed = FAILED_SSH_RE.search(line)
        if failed:
            failed_by_ip[failed.group("ip")] += 1
            failed_by_user[failed.group("user")] += 1
            continue
        invalid = INVALID_SSH_RE.search(line)
        if invalid:
            failed_by_ip[invalid.group("ip")] += 1
            failed_by_user[invalid.group("user")] += 1
            continue
        accepted = ACCEPTED_SSH_RE.search(line)
        if accepted:
            accepted_by_ip[accepted.group("ip")] += 1
            accepted_by_user[accepted.group("user")] += 1

    return {
        "failed_total": sum(failed_by_ip.values()),
        "accepted_total": sum(accepted_by_ip.values()),
        "failed_by_ip": failed_by_ip.most_common(10),
        "failed_by_user": failed_by_user.most_common(10),
        "accepted_by_ip": accepted_by_ip.most_common(10),
        "accepted_by_user": accepted_by_user.most_common(10),
    }


def parse_sshd_config(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip()
    return values


def iso_from_epoch(epoch: int) -> str | None:
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

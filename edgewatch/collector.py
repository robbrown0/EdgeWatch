from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl

# Collector intentionally runs fixed local diagnostic commands.
import subprocess  # nosec B404
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import AppConfig, Secrets, URLCheck
from .geoip import GeoIPResolver
from .linode import fetch_linode_firewall, fetch_linode_transfer
from .parsers import (
    NetworkCounters,
    cpu_percent,
    iso_from_epoch,
    memory_percent,
    parse_meminfo,
    parse_proc_net_dev,
    parse_proc_stat_cpu,
    parse_ss_connections,
    parse_ss_listeners,
    parse_sshd_config,
    parse_wg_dump,
    summarize_ssh_journal,
)
from .plex import (
    cache_plex_artwork,
    fetch_plex_sessions,
    summarize_plex,
)

CommandRunner = Callable[[list[str], float], tuple[int, str, str]]


DEFAULT_SERVICE_PORT_NAMES = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    51820: "WireGuard",
    32400: "Plex",
}

CADDY_ACTIVITY_TAIL_BYTES = 2_000_000
CADDY_ACTIVITY_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


SEVERITY_POINTS = {"low": 2, "medium": 6, "high": 13, "critical": 22}
SSHD_DISABLED = "no"


def run_command(args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        # Arguments are passed as an argv list and shell execution is never used.
        result = subprocess.run(  # nosec B603
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _network_counters(interface: str) -> NetworkCounters | None:
    parsed = parse_proc_net_dev(_read_text("/proc/net/dev"))
    if interface in parsed:
        return parsed[interface]
    base = Path("/sys/class/net") / interface / "statistics"
    try:
        def value(name: str) -> int:
            return int(_read_text(base / name).strip())

        return NetworkCounters(
            rx_bytes=value("rx_bytes"),
            rx_errors=value("rx_errors"),
            rx_drops=value("rx_dropped"),
            tx_bytes=value("tx_bytes"),
            tx_errors=value("tx_errors"),
            tx_drops=value("tx_dropped"),
        )
    except (OSError, ValueError):
        return None


def _fmt_bytes(value: float) -> str:
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    size = float(max(0, value))
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1
    return f"{size:.1f} {units[index]}" if index else f"{int(size)} {units[index]}"


def _fmt_rate(value: float) -> str:
    return f"{_fmt_bytes(value)}/s"


def _normalize_ip(value: str) -> str:
    """Normalize socket addresses while preserving genuine IPv6."""

    raw = str(value or "").split("%", 1)[0]

    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return raw

    if isinstance(parsed, ipaddress.IPv6Address):
        mapped = parsed.ipv4_mapped
        if mapped is not None:
            return str(mapped)

    return str(parsed)


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(_normalize_ip(value))
    except ValueError:
        return False
    return ip.is_global


def _service_name_for_port(port: int, labels: dict[int, str] | None = None) -> str:
    names = labels or DEFAULT_SERVICE_PORT_NAMES
    return names.get(port, f"Port {port}")


def _resolve_host(hostname: str, port: int = 443) -> list[str]:
    try:
        addresses = {
            _normalize_ip(item[4][0])
            for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
        return sorted(addresses)
    except OSError:
        return []


def _tls_certificate(hostname: str, port: int, timeout: float, verify: bool) -> dict[str, object]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((hostname, port), timeout=timeout) as raw_socket,
            context.wrap_socket(
                raw_socket,
                server_hostname=hostname if verify else None,
            ) as tls_socket,
        ):
            certificate = tls_socket.getpeercert()
            cipher = tls_socket.cipher()
            protocol = tls_socket.version() or ""
        not_after = certificate.get("notAfter")
        expires_at = None
        days_remaining = None
        if not_after:
            expires_epoch = ssl.cert_time_to_seconds(str(not_after))
            expires_at = datetime.fromtimestamp(expires_epoch, tz=timezone.utc).isoformat()
            days_remaining = round((expires_epoch - time.time()) / 86400, 1)
        issuer_parts = certificate.get("issuer") or []
        issuer = ""
        for group in issuer_parts:
            for key, value in group:
                if key in {"organizationName", "commonName"}:
                    issuer = str(value)
                    break
            if issuer:
                break
        return {
            "available": True,
            "expires_at": expires_at,
            "days_remaining": days_remaining,
            "issuer": issuer,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "",
        }
    except Exception as exc:
        return {
            "available": False,
            "expires_at": None,
            "days_remaining": None,
            "issuer": "",
            "protocol": "",
            "cipher": "",
            "detail": str(exc)[:180],
        }


def _safe_url_check(check: URLCheck) -> dict[str, object]:
    parsed = urllib.parse.urlparse(check.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {
            "name": check.name,
            "url": check.url,
            "ok": False,
            "status": "invalid URL",
            "latency_ms": None,
            "detail": "Only http and https checks are supported",
            "resolved_ips": [],
            "certificate": None,
        }

    context = None
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        if not check.tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(
        check.url,
        headers={
            "User-Agent": "EdgeWatch/0.5.4",
            "Accept": "*/*",
            "Connection": "close",
        },
        method="GET",
    )
    resolved_ips = _resolve_host(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    certificate = None
    if parsed.scheme == "https":
        certificate = _tls_certificate(
            parsed.hostname,
            parsed.port or 443,
            check.timeout_seconds,
            check.tls_verify,
        )
    started = time.monotonic()
    try:
        # The URL scheme is explicitly restricted to HTTP or HTTPS above.
        with urllib.request.urlopen(  # nosec B310
            request, timeout=check.timeout_seconds, context=context
        ) as response:
            status = int(response.status)
            response.read(4096)
        latency_ms = round((time.monotonic() - started) * 1000)
        ok = check.expected_status_min <= status <= check.expected_status_max
        return {
            "name": check.name,
            "url": check.url,
            "ok": ok,
            "status": status,
            "latency_ms": latency_ms,
            "detail": "reachable" if ok else "unexpected HTTP status",
            "resolved_ips": resolved_ips,
            "certificate": certificate,
            "certificate_warn_days": check.certificate_warn_days,
        }
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.monotonic() - started) * 1000)
        status = int(exc.code)
        ok = check.expected_status_min <= status <= check.expected_status_max
        return {
            "name": check.name,
            "url": check.url,
            "ok": ok,
            "status": status,
            "latency_ms": latency_ms,
            "detail": "reachable" if ok else str(exc.reason),
            "resolved_ips": resolved_ips,
            "certificate": certificate,
            "certificate_warn_days": check.certificate_warn_days,
        }
    except Exception as exc:
        return {
            "name": check.name,
            "url": check.url,
            "ok": False,
            "status": "failed",
            "latency_ms": None,
            "detail": str(exc)[:180],
            "resolved_ips": resolved_ips,
            "certificate": certificate,
            "certificate_warn_days": check.certificate_warn_days,
        }


class Collector:
    def __init__(
        self,
        config: AppConfig,
        secrets: Secrets | None = None,
        command_runner: CommandRunner = run_command,
        geoip_resolver: GeoIPResolver | None = None,
    ):
        self.config = config
        self.secrets = secrets or Secrets()
        self.service_port_names = dict(DEFAULT_SERVICE_PORT_NAMES)
        self.service_port_names.update(dict(config.service_port_names))
        self.command_runner = command_runner
        self.geoip = geoip_resolver or GeoIPResolver(config.geoip)
        self.previous_cpu: tuple[int, int] | None = None
        self.previous_network: dict[str, tuple[int, int]] = {}
        self.previous_sample_monotonic: float | None = None
        self.connection_first_seen: dict[str, int] = {}
        self.connection_last_seen: dict[str, int] = {}
        self.recent_public_peers: dict[str, dict[str, object]] = {}
        self.last_security: dict[str, object] = {}
        self.last_security_at = 0.0
        self.last_maintenance: dict[str, object] = {}
        self.last_maintenance_at = 0.0
        self.last_url_checks: list[dict[str, object]] = []
        self.last_url_checks_at = 0.0
        self.last_linode: dict[str, object] = {"enabled": config.linode.enabled, "configured": False, "ok": True}
        self.last_linode_at = 0.0
        self.last_linode_transfer: dict[str, object] = {
            "ok": False,
            "configured": False,
            "status": "not checked",
        }
        self.last_linode_transfer_at = 0.0
        self.last_caddy_activity: dict[
            str,
            dict[str, object],
        ] = {}
        self.last_caddy_activity_at = 0.0
        self.boot_id = self._boot_id()

    def _boot_id(self) -> str:
        try:
            return _read_text("/proc/sys/kernel/random/boot_id").strip()
        except OSError:
            return "unknown"

    def _service_states(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for name in self.config.services:
            code, stdout, stderr = self.command_runner(["systemctl", "is-active", name], 3.0)
            state = stdout.strip() or "unknown"
            active = code == 0 and state == "active"
            result.append(
                {
                    "name": name,
                    "active": active,
                    "state": state,
                    "detail": stderr[:160] if not active and stderr else "",
                }
            )
        return result

    def _failed_units(self) -> list[str]:
        _code, stdout, _stderr = self.command_runner(
            ["systemctl", "--failed", "--no-legend", "--plain"], 5.0
        )
        units: list[str] = []
        for line in stdout.splitlines():
            first = line.split(None, 1)[0] if line.strip() else ""
            if first and first != "0":
                units.append(first)
        return units[:20]

    def _firewall_state(self) -> dict[str, object]:
        # EdgeWatch structured UFW rules
        code, stdout, stderr = self.command_runner(
            ["ufw", "status", "verbose"],
            5.0,
        )

        if code != 0:
            return {
                "available": False,
                "active": False,
                "status": "unavailable",
                "detail": (
                    stderr[:160]
                    or "ufw command failed"
                ),
                "default_policy": "",
                "rule_count": 0,
                "rules": [],
            }

        lines = stdout.splitlines()
        first = lines[0] if lines else ""

        active = (
            "status: active"
            in first.lower()
        )

        default_policy = next(
            (
                line.strip()
                for line in lines
                if line.lower().startswith(
                    "default:"
                )
            ),
            "",
        )

        numbered_code, numbered_stdout, numbered_stderr = (
            self.command_runner(
                ["ufw", "status", "numbered"],
                5.0,
            )
        )

        rules: list[dict[str, object]] = []

        if numbered_code == 0:
            for raw_line in numbered_stdout.splitlines():
                stripped = raw_line.strip()

                if not stripped.startswith("["):
                    continue

                match = re.match(
                    r"^\[\s*(\d+)\]\s+"
                    r"(.*?)\s{2,}"
                    r"([A-Z]+(?:\s+(?:IN|OUT))?)"
                    r"\s{2,}(.*)$",
                    stripped,
                )

                if not match:
                    rules.append(
                        {
                            "number": len(rules) + 1,
                            "destination": "",
                            "action": "",
                            "source": "",
                            "ip_version": "",
                            "raw": stripped[:300],
                        }
                    )
                    continue

                number = int(match.group(1))
                destination = match.group(2).strip()
                action = match.group(3).strip()
                source = match.group(4).strip()

                ipv6 = (
                    "(v6)" in destination.lower()
                    or "(v6)" in source.lower()
                )

                destination = re.sub(
                    r"\s*\(v6\)\s*$",
                    "",
                    destination,
                    flags=re.IGNORECASE,
                ).strip()

                source = re.sub(
                    r"\s*\(v6\)\s*$",
                    "",
                    source,
                    flags=re.IGNORECASE,
                ).strip()

                rules.append(
                    {
                        "number": number,
                        "destination": destination,
                        "action": action,
                        "source": source,
                        "ip_version": (
                            "IPv6"
                            if ipv6
                            else "IPv4"
                        ),
                        "raw": stripped[:300],
                    }
                )

        return {
            "available": True,
            "active": active,
            "status": first or "unknown",
            "default_policy": default_policy,
            "rule_count": len(rules),
            "rules": rules,
            "rule_detail": (
                ""
                if numbered_code == 0
                else numbered_stderr[:160]
            ),
        }
    def _listeners(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        _code, stdout, _stderr = self.command_runner(["ss", "-H", "-lntup"], 5.0)
        listeners = parse_ss_listeners(stdout)
        rows: list[dict[str, object]] = []
        unexpected: list[dict[str, object]] = []
        for item in sorted(listeners, key=lambda x: (x.protocol, x.port, x.host)):
            protocol = "tcp" if item.protocol.startswith("tcp") else "udp"
            allowed = (
                item.port in self.config.allowed_public_tcp_ports
                if protocol == "tcp"
                else item.port in self.config.allowed_public_udp_ports
            )
            row = {
                "protocol": protocol,
                "host": item.host,
                "port": item.port,
                "service": _service_name_for_port(item.port, self.service_port_names),
                "process": item.process,
                "pid": item.pid,
                "public_bind": item.public_bind,
                "allowed": allowed or not item.public_bind,
            }
            rows.append(row)
            if item.public_bind and not allowed:
                unexpected.append(row)
        return rows, unexpected

    def _public_interface_ips(self) -> list[str]:
        code, stdout, _stderr = self.command_runner(
            ["ip", "-j", "address", "show", "dev", self.config.primary_interface], 5.0
        )
        if code != 0:
            return []
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        values: list[str] = []
        for interface in payload if isinstance(payload, list) else []:
            for item in interface.get("addr_info", []) if isinstance(interface, dict) else []:
                address = str(item.get("local") or "")
                if _is_public_ip(address):
                    values.append(address)
        return sorted(set(values))

    def _caddy_activity(
        self,
        now_epoch: int,
    ) -> dict[str, dict[str, object]]:
        """Return recent sanitized HTTP activity grouped by client IP."""

        now_monotonic = time.monotonic()

        if (
            self.last_caddy_activity_at
            and now_monotonic - self.last_caddy_activity_at < 15
        ):
            return self.last_caddy_activity

        discovered: dict[str, dict[str, object]] = {}

        for source in self.config.caddy_activity_sources:
            log_path = source.log_path
            site_name = source.name

            try:
                size = log_path.stat().st_size

                with log_path.open("rb") as handle:
                    start = max(
                        0,
                        size - CADDY_ACTIVITY_TAIL_BYTES,
                    )
                    handle.seek(start)

                    if start:
                        handle.readline()

                    payload = handle.read(
                        CADDY_ACTIVITY_TAIL_BYTES
                    )
            except OSError:
                continue

            for raw_line in payload.splitlines():
                try:
                    event = json.loads(
                        raw_line.decode(
                            "utf-8",
                            errors="replace",
                        )
                    )
                except (
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                ):
                    continue

                if not isinstance(event, dict):
                    continue

                request = event.get("request")

                if not isinstance(request, dict):
                    continue

                remote_ip = (
                    request.get("client_ip")
                    or request.get("remote_ip")
                    or ""
                )

                ip = _normalize_ip(str(remote_ip))

                if not _is_public_ip(ip):
                    continue

                try:
                    event_ts = int(
                        float(event.get("ts") or 0)
                    )
                except (TypeError, ValueError):
                    continue

                if event_ts <= 0:
                    continue

                if (
                    now_epoch - event_ts
                    > CADDY_ACTIVITY_MAX_AGE_SECONDS
                ):
                    continue

                headers = request.get("headers")

                if not isinstance(headers, dict):
                    headers = {}

                def header(
                    name: str,
                    source_headers: dict[object, object] = headers,
                ) -> str:
                    for key, value in source_headers.items():
                        if str(key).lower() != name.lower():
                            continue

                        if isinstance(value, list):
                            return ", ".join(
                                str(item)
                                for item in value
                                if item is not None
                            )

                        return str(value or "")

                    return ""

                host = str(
                    request.get("host")
                    or header("Host")
                    or ""
                ).lower()

                if ":" in host:
                    host = host.split(":", 1)[0]

                raw_uri = str(
                    request.get("uri")
                    or "/"
                )

                # Store the path only. Query strings may contain
                # credentials or Plex tokens.
                request_path = (
                    urllib.parse.urlsplit(raw_uri).path
                    or "/"
                )

                path_lower = request_path.lower()

                activity_kind = source.kind
                activity_label = source.label

                if source.hosts and host not in source.hosts:
                    continue

                if activity_kind == "plex":
                    if (
                        path_lower
                        == "/:/eventsource/notifications"
                    ):
                        activity_kind = "plex_notification"
                        activity_label = (
                            "Plex notification channel"
                        )
                    elif (
                        "/video/:/transcode/" in path_lower
                        or "/library/parts/" in path_lower
                    ):
                        activity_kind = "plex_media"
                        activity_label = (
                            "Plex media request"
                        )

                activity: dict[str, object] = {
                    "ip": ip,
                    "ts": event_ts,
                    "site": site_name,
                    "host": host,
                    "method": str(
                        request.get("method") or ""
                    ),
                    "path": request_path,
                    "status": event.get("status"),
                    "duration_seconds": event.get(
                        "duration"
                    ),
                    "kind": activity_kind,
                    "label": activity_label,
                    "user_agent": header("User-Agent"),
                    "client_identifier": header(
                        "X-Plex-Client-Identifier"
                    ),
                    "device": header("X-Plex-Device"),
                    "device_name": header(
                        "X-Plex-Device-Name"
                    ),
                    "device_vendor": header(
                        "X-Plex-Device-Vendor"
                    ),
                    "model": header("X-Plex-Model"),
                    "platform": header(
                        "X-Plex-Platform"
                    ),
                    "platform_version": header(
                        "X-Plex-Platform-Version"
                    ),
                    "product": header("X-Plex-Product"),
                    "provides": header(
                        "X-Plex-Provides"
                    ),
                    "version": header("X-Plex-Version"),
                }

                previous = discovered.get(ip)

                if previous is None:
                    previous = self.last_caddy_activity.get(
                        ip
                    )

                merged: dict[str, object] = {}

                if (
                    isinstance(previous, dict)
                    and previous.get("host") == host
                ):
                    merged.update(previous)

                for key, value in activity.items():
                    if value not in ("", None, []):
                        merged[key] = value

                existing = discovered.get(ip)

                if (
                    not isinstance(existing, dict)
                    or event_ts
                    >= int(existing.get("ts") or 0)
                ):
                    discovered[ip] = merged

        combined = dict(self.last_caddy_activity)

        for ip, activity in discovered.items():
            current = combined.get(ip)

            if (
                not isinstance(current, dict)
                or int(activity.get("ts") or 0)
                >= int(current.get("ts") or 0)
            ):
                combined[ip] = activity

        for ip in list(combined):
            activity_ts = int(
                combined[ip].get("ts") or 0
            )

            if (
                not activity_ts
                or now_epoch - activity_ts
                > CADDY_ACTIVITY_MAX_AGE_SECONDS
            ):
                combined.pop(ip, None)

        self.last_caddy_activity = combined
        self.last_caddy_activity_at = now_monotonic

        return self.last_caddy_activity

    def _connections(self, listeners: list[dict[str, object]], now_epoch: int) -> dict[str, object]:
        _code, stdout, _stderr = self.command_runner(
            ["ss", "-H", "-t", "-n", "-p", "state", "established"], 5.0
        )
        flows = parse_ss_connections(stdout)
        caddy_activity = self._caddy_activity(
            now_epoch
        )
        listener_ports = {
            int(item["port"])
            for item in listeners
            if item.get("protocol") == "tcp" and item.get("public_bind")
        }
        service_counts: Counter[str] = Counter()
        public: dict[str, dict[str, object]] = {}
        internal: dict[str, dict[str, object]] = {}
        public_connection_count = 0
        internal_connection_count = 0
        local_connection_count = 0
        other_connection_count = 0

        alias_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = []
        for alias in self.config.peer_aliases:
            try:
                alias_networks.append((
                    ipaddress.ip_network(alias.allowed_ip, strict=False),
                    alias.name,
                    alias.scope,
                ))
            except ValueError:
                continue

        def alias_for(address: str, scope: str) -> str:
            normalized = _normalize_ip(address)

            try:
                parsed = ipaddress.ip_address(normalized)
            except ValueError:
                return normalized
            for network, name, alias_scope in alias_networks:
                if alias_scope not in {"any", scope}:
                    continue
                if parsed in network:
                    return name
            return address

        def aggregate(
            collection: dict[str, dict[str, object]],
            flow_ip: str,
            flow,
            direction: str,
        ) -> None:
            entry = collection.setdefault(
                flow_ip,
                {
                    "ip": flow_ip,
                    "name": alias_for(
                        flow_ip,
                        "public" if collection is public else "private",
                    ),
                    "connections": 0,
                    "inbound": 0,
                    "outbound": 0,
                    "processes": Counter(),
                    "services": Counter(),
                    "local_ports": Counter(),
                    "remote_ports": Counter(),
                },
            )
            entry["connections"] = int(entry["connections"]) + 1
            entry[direction] = int(entry[direction]) + 1
            entry["processes"][flow.process or "kernel/unknown"] += 1
            service_port = flow.local_port if direction == "inbound" else flow.remote_port
            entry["services"][_service_name_for_port(service_port, self.service_port_names)] += 1
            entry["local_ports"][flow.local_port] += 1
            entry["remote_ports"][flow.remote_port] += 1

        for flow in flows:
            if flow.local_port in self.service_port_names:
                service_counts[_service_name_for_port(flow.local_port, self.service_port_names)] += 1
            if flow.remote_port in self.service_port_names:
                service_counts[_service_name_for_port(flow.remote_port, self.service_port_names)] += 1

            direction = "inbound" if flow.local_port in listener_ports else "outbound"
            remote = _normalize_ip(flow.remote_host)
            if _is_public_ip(remote):
                public_connection_count += 1
                aggregate(public, remote, flow, direction)
                continue

            try:
                parsed_remote = ipaddress.ip_address(remote)
            except ValueError:
                other_connection_count += 1
                continue
            if parsed_remote.is_loopback:
                local_connection_count += 1
            elif not parsed_remote.is_global:
                internal_connection_count += 1
                aggregate(internal, remote, flow, direction)
            else:
                other_connection_count += 1

        peers: list[dict[str, object]] = []
        for ip, entry in public.items():
            self.connection_first_seen.setdefault(ip, now_epoch)
            self.connection_last_seen[ip] = now_epoch
            geo = self.geoip.lookup(ip)
            peer = {
                "ip": ip,
                "name": entry["name"],
                "connections": entry["connections"],
                "inbound": entry["inbound"],
                "outbound": entry["outbound"],
                "direction": "mixed" if entry["inbound"] and entry["outbound"] else ("inbound" if entry["inbound"] else "outbound"),
                "processes": [
                    {"name": name, "connections": count}
                    for name, count in entry["processes"].most_common(4)
                ],
                "services": [
                    {"name": name, "connections": count}
                    for name, count in entry["services"].most_common(4)
                ],
                "local_ports": [port for port, _count in entry["local_ports"].most_common(6)],
                "remote_ports": [port for port, _count in entry["remote_ports"].most_common(6)],
                "first_seen_ts": self.connection_first_seen[ip],
                "last_seen_ts": now_epoch,
                "active": True,
                **geo,
            }

            activity = caddy_activity.get(ip)

            if isinstance(activity, dict):
                peer["activity"] = dict(activity)

                device_name = str(
                    activity.get("device_name") or ""
                )

                if device_name:
                    peer["display_name"] = device_name
            peers.append(peer)
            self.recent_public_peers[ip] = dict(peer)

        recent_cutoff = now_epoch - self.config.flow_recent_seconds
        for ip in list(self.recent_public_peers):
            last_seen = int(self.recent_public_peers[ip].get("last_seen_ts", 0))
            if last_seen < recent_cutoff:
                self.recent_public_peers.pop(ip, None)

        recent_peers: list[dict[str, object]] = []
        active_ips = set(public)
        for ip, stored in self.recent_public_peers.items():
            row = dict(stored)
            row["active"] = ip in active_ips
            row["seconds_since_seen"] = max(0, now_epoch - int(row.get("last_seen_ts", now_epoch)))
            recent_peers.append(row)

        stale_before = now_epoch - max(600, self.config.flow_recent_seconds)
        for ip in list(self.connection_last_seen):
            if self.connection_last_seen[ip] < stale_before:
                self.connection_last_seen.pop(ip, None)
                self.connection_first_seen.pop(ip, None)

        def normalized_internal(entry: dict[str, object]) -> dict[str, object]:
            return {
                "ip": entry["ip"],
                "name": entry["name"],
                "connections": entry["connections"],
                "inbound": entry["inbound"],
                "outbound": entry["outbound"],
                "direction": "mixed" if entry["inbound"] and entry["outbound"] else ("inbound" if entry["inbound"] else "outbound"),
                "processes": [
                    {"name": name, "connections": count}
                    for name, count in entry["processes"].most_common(4)
                ],
                "services": [
                    {"name": name, "connections": count}
                    for name, count in entry["services"].most_common(4)
                ],
                "local_ports": [port for port, _count in entry["local_ports"].most_common(6)],
                "remote_ports": [port for port, _count in entry["remote_ports"].most_common(6)],
            }

        peers.sort(key=lambda item: (-int(item["connections"]), str(item["ip"])))
        recent_peers.sort(
            key=lambda item: (
                not bool(item.get("active")),
                -int(item.get("connections", 0)),
                -int(item.get("last_seen_ts", 0)),
                str(item.get("ip", "")),
            )
        )
        internal_peers = sorted(
            (normalized_internal(entry) for entry in internal.values()),
            key=lambda item: (-int(item["connections"]), str(item["name"])),
        )
        public_ips = self._public_interface_ips()
        origin = None
        for ip in public_ips:
            geo = self.geoip.lookup(ip)
            if geo.get("located"):
                origin = {
                    "ip": ip,
                    "name": platform.node(),
                    "label": "EdgeWatch VPS",
                    **geo,
                }
                break
        return {
            "established": len(flows),
            "public_connection_count": public_connection_count,
            "internal_connection_count": internal_connection_count,
            "local_connection_count": local_connection_count,
            "other_connection_count": other_connection_count,
            "public_peer_count": len(peers),
            "unique_public_peer_count": len(peers),
            "recent_public_peer_count": len(recent_peers),
            "loopback_connection_count": local_connection_count,
            "flow_recent_seconds": self.config.flow_recent_seconds,
            "public_peers": peers[:75],
            "recent_public_peers": recent_peers[:100],
            "internal_peers": internal_peers[:75],
            "top_public_peers": [
                {"ip": item["ip"], "connections": item["connections"], "country_code": item.get("country_code", "")}
                for item in peers[:10]
            ],
            "services": [
                {"name": name, "connections": count}
                for name, count in service_counts.most_common()
            ],
            "origin": origin,
            "public_interface_ips": public_ips,
        }

    def _wireguard(self, now_epoch: int) -> list[dict[str, object]]:
        aliases = {
            item.allowed_ip: item.name
            for item in self.config.peer_aliases
            if item.scope in {"any", "private", "wireguard"}
        }
        peers_out: list[dict[str, object]] = []
        for interface in self.config.wireguard_interfaces:
            code, stdout, stderr = self.command_runner(["wg", "show", interface, "dump"], 5.0)
            if code != 0:
                peers_out.append(
                    {
                        "interface": interface,
                        "name": interface,
                        "ok": False,
                        "online": False,
                        "error": stderr[:160] or "wg show failed",
                    }
                )
                continue
            for peer in parse_wg_dump(stdout, interface):
                age = None if peer.latest_handshake <= 0 else max(0, now_epoch - peer.latest_handshake)
                online = age is not None and age <= self.config.peer_stale_seconds
                alias = next((aliases.get(ip) for ip in peer.allowed_ips if aliases.get(ip)), None)
                peers_out.append(
                    {
                        "interface": interface,
                        "name": alias or f"Peer {peer.public_key[:8]}",
                        "public_key_short": f"{peer.public_key[:8]}…{peer.public_key[-6:]}",
                        "endpoint": peer.endpoint,
                        "allowed_ips": list(peer.allowed_ips),
                        "latest_handshake": iso_from_epoch(peer.latest_handshake),
                        "handshake_age_seconds": age,
                        "rx_bytes": peer.transfer_rx,
                        "tx_bytes": peer.transfer_tx,
                        "rx_human": _fmt_bytes(peer.transfer_rx),
                        "tx_human": _fmt_bytes(peer.transfer_tx),
                        "online": online,
                        "ok": online,
                    }
                )
        return peers_out

    def _ssh_security(self) -> dict[str, object]:
        _code, stdout, _stderr = self.command_runner(
            ["journalctl", "-u", "ssh", "--since", "15 minutes ago", "--no-pager", "-o", "cat"],
            8.0,
        )
        return summarize_ssh_journal(stdout.splitlines())

    def _sshd_hardening(self) -> dict[str, object]:
        code, stdout, stderr = self.command_runner(["sshd", "-T"], 8.0)
        if code != 0:
            return {"available": False, "detail": stderr[:180] or "sshd -T failed", "controls": []}
        values = parse_sshd_config(stdout)
        password = values.get("passwordauthentication", "unknown")
        root = values.get("permitrootlogin", "unknown")
        pubkey = values.get("pubkeyauthentication", "unknown")
        max_auth = values.get("maxauthtries", "unknown")
        try:
            max_auth_ok = int(max_auth) <= 6
        except ValueError:
            max_auth_ok = False
        controls = [
            # "no" is an sshd setting value, not a password.
            {"name": "Password authentication", "value": password, "ok": password == SSHD_DISABLED},
            {"name": "Root login", "value": root, "ok": root == SSHD_DISABLED, "warning": root in {"prohibit-password", "without-password"}},
            {"name": "Public key authentication", "value": pubkey, "ok": pubkey == "yes"},
            {"name": "Max authentication tries", "value": max_auth, "ok": max_auth_ok},
        ]
        return {
            "available": True,
            "controls": controls,
            "password_authentication": password,
            "permit_root_login": root,
            "pubkey_authentication": pubkey,
            "max_auth_tries": max_auth,
            "allow_users": values.get("allowusers", ""),
            "allow_groups": values.get("allowgroups", ""),
        }

    def _pending_updates(self) -> int:
        code, stdout, _stderr = self.command_runner(["apt", "list", "--upgradable"], 20.0)
        if code not in {0, 100}:
            return 0
        return sum(1 for line in stdout.splitlines() if "/" in line and not line.startswith("Listing"))

    def _automatic_updates(self) -> dict[str, object]:
        enabled_code, enabled_out, _ = self.command_runner(
            ["systemctl", "is-enabled", "apt-daily-upgrade.timer"], 4.0
        )
        active_code, active_out, _ = self.command_runner(
            ["systemctl", "is-active", "apt-daily-upgrade.timer"], 4.0
        )
        enabled = enabled_code == 0 and enabled_out.strip() in {"enabled", "static"}
        active = active_code == 0 and active_out.strip() == "active"
        return {"enabled": enabled, "active": active, "ok": enabled and active}

    def _apparmor(self) -> dict[str, object]:
        code, stdout, _stderr = self.command_runner(["systemctl", "is-active", "apparmor"], 4.0)
        active = code == 0 and stdout.strip() == "active"
        profiles = None
        if active:
            _aa_code, aa_out, _aa_err = self.command_runner(["aa-status"], 5.0)
            for line in aa_out.splitlines():
                if "profiles are loaded" in line:
                    with suppress(ValueError, IndexError):
                        profiles = int(line.strip().split()[0])
                    break
        return {"available": shutil.which("aa-status") is not None, "active": active, "profiles": profiles, "ok": active}

    def _fail2ban(self) -> dict[str, object]:
        if shutil.which("fail2ban-client") is None:
            return {"installed": False, "active": False, "jails": [], "ok": True}
        code, stdout, _stderr = self.command_runner(["systemctl", "is-active", "fail2ban"], 4.0)
        active = code == 0 and stdout.strip() == "active"
        jails: list[str] = []
        if active:
            _status_code, status_out, _status_err = self.command_runner(["fail2ban-client", "status"], 5.0)
            for line in status_out.splitlines():
                if "Jail list:" in line:
                    jails = [item.strip() for item in line.split(":", 1)[1].split(",") if item.strip()]
        return {"installed": True, "active": active, "jails": jails, "ok": active}

    @staticmethod
    def _read_sysctl_file(path: str) -> str:
        try:
            return _read_text(path).strip()
        except OSError:
            return "unavailable"

    def _kernel_hardening(self) -> dict[str, object]:
        specs = [
            ("IPv4 reverse path filtering", "/proc/sys/net/ipv4/conf/all/rp_filter", {"1", "2"}),
            ("IPv4 ICMP redirects", "/proc/sys/net/ipv4/conf/all/accept_redirects", {"0"}),
            ("IPv4 source routes", "/proc/sys/net/ipv4/conf/all/accept_source_route", {"0"}),
            ("IPv4 send redirects", "/proc/sys/net/ipv4/conf/all/send_redirects", {"0"}),
            ("IPv6 ICMP redirects", "/proc/sys/net/ipv6/conf/all/accept_redirects", {"0"}),
            ("IPv6 source routes", "/proc/sys/net/ipv6/conf/all/accept_source_route", {"0"}),
        ]
        controls = []
        for name, path, expected in specs:
            value = self._read_sysctl_file(path)
            controls.append({"name": name, "value": value, "ok": value in expected})
        return {"controls": controls, "ok": all(item["ok"] for item in controls)}

    def _reboot_required(self) -> bool:
        return Path("/var/run/reboot-required").exists()

    def _time_sync(self) -> dict[str, object]:
        code, stdout, stderr = self.command_runner(
            ["timedatectl", "show", "--property=NTPSynchronized", "--value"], 4.0
        )
        value = stdout.strip().lower()
        synchronized = code == 0 and value == "yes"
        return {
            "available": code == 0,
            "synchronized": synchronized,
            "ok": synchronized,
            "detail": stderr[:160] if code != 0 else value or "unknown",
        }

    def _service_journal_health(self) -> dict[str, object]:
        # EdgeWatch structured service journal samples
        units = [
            name
            for name in self.config.services
            if name in {
                "caddy",
                "ssh",
                "wg-quick@wg0",
            }
        ]

        if not units:
            return {
                "warning_count": 0,
                "samples": [],
                "ok": True,
            }

        args = ["journalctl"]

        for unit in units:
            args.extend(["-u", unit])

        args.extend(
            [
                "--since",
                "15 minutes ago",
                "--priority",
                "warning",
                "--no-pager",
                "-o",
                "json",
            ]
        )

        code, stdout, stderr = self.command_runner(
            args,
            8.0,
        )

        if code != 0:
            return {
                "available": False,
                "warning_count": 0,
                "samples": [],
                "ok": True,
                "detail": stderr[:160],
            }

        samples: list[dict[str, str]] = []

        for raw_line in stdout.splitlines():
            raw_line = raw_line.strip()

            if not raw_line:
                continue

            try:
                entry = json.loads(raw_line)
            except (json.JSONDecodeError, TypeError):
                continue

            raw_message = entry.get("MESSAGE", "")

            if isinstance(raw_message, list):
                raw_message = " ".join(
                    str(value)
                    for value in raw_message
                )

            message = " ".join(
                str(raw_message).split()
            )[:500]

            if not message:
                continue

            service = str(
                entry.get("_SYSTEMD_UNIT")
                or entry.get("UNIT")
                or entry.get("SYSLOG_IDENTIFIER")
                or "unknown"
            ).strip()

            if service.endswith(".service"):
                service = service[:-8]

            raw_timestamp = str(
                entry.get("__REALTIME_TIMESTAMP")
                or ""
            ).strip()

            timestamp = ""

            if raw_timestamp:
                try:
                    timestamp = datetime.fromtimestamp(
                        int(raw_timestamp) / 1_000_000,
                        tz=timezone.utc,
                    ).isoformat()
                except (TypeError, ValueError, OSError):
                    timestamp = raw_timestamp

            samples.append(
                {
                    "service": service or "unknown",
                    "timestamp": timestamp,
                    "message": message,
                }
            )

        return {
            "available": True,
            "warning_count": len(samples),
            "samples": samples[-8:],
            "ok": not samples,
        }
    def _maintenance_snapshot(self) -> dict[str, object]:
        with ThreadPoolExecutor(max_workers=6) as executor:
            pending_future = executor.submit(self._pending_updates)
            automatic_future = executor.submit(self._automatic_updates)
            apparmor_future = executor.submit(self._apparmor)
            fail2ban_future = executor.submit(self._fail2ban)
            time_sync_future = executor.submit(self._time_sync)
            kernel_future = executor.submit(self._kernel_hardening)
            return {
                "pending_updates": pending_future.result(),
                "reboot_required": self._reboot_required(),
                "automatic_updates": automatic_future.result(),
                "apparmor": apparmor_future.result(),
                "fail2ban": fail2ban_future.result(),
                "time_sync": time_sync_future.result(),
                "kernel": kernel_future.result(),
            }

    def _security_snapshot(self) -> dict[str, object]:
        listeners, unexpected = self._listeners()
        now = time.monotonic()
        if now - self.last_maintenance_at >= self.config.maintenance_interval_seconds or not self.last_maintenance:
            self.last_maintenance = self._maintenance_snapshot()
            self.last_maintenance_at = now
        with ThreadPoolExecutor(max_workers=6) as executor:
            service_future = executor.submit(self._service_states)
            firewall_future = executor.submit(self._firewall_state)
            ssh_future = executor.submit(self._ssh_security)
            sshd_future = executor.submit(self._sshd_hardening)
            failed_future = executor.submit(self._failed_units)
            journal_future = executor.submit(self._service_journal_health)
            dynamic = {
                "services": service_future.result(),
                "firewall": firewall_future.result(),
                "ssh": ssh_future.result(),
                "sshd": sshd_future.result(),
                "failed_units": failed_future.result(),
                "service_journal": journal_future.result(),
            }
        return {
            "listeners": listeners,
            "unexpected_listeners": unexpected,
            **dynamic,
            **self.last_maintenance,
            "maintenance_age_seconds": round(max(0.0, now - self.last_maintenance_at), 1),
        }

    def _url_checks(self) -> list[dict[str, object]]:
        if not self.config.url_checks:
            return []
        with ThreadPoolExecutor(max_workers=min(8, len(self.config.url_checks))) as executor:
            return list(executor.map(_safe_url_check, self.config.url_checks))

    def _plex(self) -> dict[str, object]:
        servers = list(self.config.plex_servers)

        if not servers:
            return summarize_plex([])

        with ThreadPoolExecutor(
            max_workers=min(4, len(servers))
        ) as executor:
            results = list(
                executor.map(
                    lambda server: fetch_plex_sessions(
                        server,
                        self.secrets.plex_token_for(
                            server.name
                        ),
                    ),
                    servers,
                )
            )

        summary = summarize_plex(results)
        sessions = summary.get("sessions", [])

        if not isinstance(sessions, list):
            return summary

        servers_by_name = {
            server.name: server
            for server in servers
        }
        artwork_dir = (
            self.config.runtime_dir
            / "artwork"
        )

        def cache_session_artwork(
            session: object,
        ) -> None:
            if not isinstance(session, dict):
                return

            server_name = str(
                session.get("server") or ""
            )
            thumb = str(
                session.get("thumb") or ""
            )
            server = servers_by_name.get(
                server_name
            )

            if (
                server is None
                or not thumb
            ):
                return

            filename = cache_plex_artwork(
                server,
                self.secrets.plex_token_for(
                    server_name
                ),
                thumb,
                artwork_dir,
            )

            if filename:
                session["artwork_key"] = filename

        if sessions:
            with ThreadPoolExecutor(
                max_workers=min(
                    4,
                    len(sessions),
                )
            ) as executor:
                list(
                    executor.map(
                        cache_session_artwork,
                        sessions,
                    )
                )

        return summary

    def _linode_firewall(self) -> dict[str, object]:
        now = time.monotonic()
        if now - self.last_linode_at >= self.config.linode.check_interval_seconds or not self.last_linode_at:
            self.last_linode = fetch_linode_firewall(self.config.linode, self.secrets.linode_api_token)
            self.last_linode_at = now
        return self.last_linode

    def _linode_transfer(self) -> dict[str, object]:
        if not self.config.linode.enabled:
            return {
                "ok": False,
                "configured": False,
                "status": "disabled",
            }

        now = time.monotonic()

        if (
            now - self.last_linode_transfer_at
            >= self.config.linode.check_interval_seconds
            or not self.last_linode_transfer_at
        ):
            self.last_linode_transfer = fetch_linode_transfer(
                self.secrets.linode_api_token
            )
            self.last_linode_transfer_at = now

        return self.last_linode_transfer

    def _dns_alignment(self, public_ips: list[str]) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        public_set = set(public_ips)
        for hostname in self.config.expected_public_hostnames:
            addresses = _resolve_host(hostname)
            rows.append(
                {
                    "hostname": hostname,
                    "addresses": addresses,
                    "matches_interface": bool(public_set.intersection(addresses)),
                }
            )
        return rows

    def _risk_and_insights(
        self,
        system: dict[str, object],
        security: dict[str, object],
        network: dict[str, object],
        wireguard: list[dict[str, object]],
        urls: list[dict[str, object]],
        plex: dict[str, object],
        linode: dict[str, object],
        geoip_status: dict[str, object],
        dns_alignment: list[dict[str, object]],
    ) -> dict[str, object]:
        insights: list[dict[str, object]] = []
        category_score: Counter[str] = Counter()

        def add(
            severity: str,
            category: str,
            title: str,
            detail: str,
            remediation: str,
            fingerprint: str,
            points: int | None = None,
        ) -> None:
            score = SEVERITY_POINTS.get(severity, 0) if points is None else points
            category_score[category] += score
            insights.append(
                {
                    "severity": severity,
                    "category": category,
                    "title": title,
                    "detail": detail,
                    "remediation": remediation,
                    "fingerprint": fingerprint,
                    "score": score,
                }
            )

        firewall = security.get("firewall", {})
        if not firewall.get("active"):
            add(
                "high", "Exposure", "Host firewall is not active",
                "UFW is unavailable or not reporting an active ruleset.",
                "Enable UFW only after confirming SSH access remains permitted from your trusted source.",
                "ufw-inactive", 18,
            )

        unexpected = security.get("unexpected_listeners", [])
        if unexpected:
            ports = ", ".join(f"{item.get('protocol')}/{item.get('port')}" for item in unexpected)
            add(
                "high", "Exposure", "Unexpected public listeners detected",
                f"Public sockets outside the configured allowlist: {ports}.",
                "Confirm ownership, then close the socket or add an intentional allowlist entry.",
                "unexpected-public-listeners", 20,
            )

        if linode.get("enabled"):
            if not linode.get("configured"):
                add(
                    "medium", "Exposure", "Linode Cloud Firewall visibility is incomplete",
                    str(linode.get("status") or "The API integration is missing its firewall ID or read-only token."),
                    "Configure a read-only Linode token in secrets.toml and the firewall ID in config.toml.",
                    "linode-firewall-unconfigured", 4,
                )
            elif not linode.get("ok"):
                add(
                    "high", "Exposure", "Linode Cloud Firewall is not in the expected state",
                    f"Status {linode.get('status')}; attached {linode.get('attached', False)}; inbound policy {linode.get('inbound_policy', 'unknown')}.",
                    "Attach the selected Cloud Firewall to this Linode, enable it, and use a default inbound DROP policy.",
                    "linode-firewall-state", 18,
                )

        sshd = security.get("sshd", {})
        if sshd.get("available"):
            if sshd.get("password_authentication") != SSHD_DISABLED:
                add(
                    "high", "Identity", "SSH password authentication is enabled",
                    f"Effective sshd value is {sshd.get('password_authentication')}.",
                    "Verify key-based access, then set PasswordAuthentication no and validate sshd before reloading.",
                    "ssh-password-enabled", 18,
                )
            root_login = str(sshd.get("permit_root_login") or "unknown")
            if root_login == "yes":
                add(
                    "high", "Identity", "Direct SSH root login is enabled",
                    "The effective sshd configuration permits direct root login.",
                    "Use an administrative account with sudo and set PermitRootLogin no.",
                    "ssh-root-login", 18,
                )
            elif root_login in {"prohibit-password", "without-password"}:
                add(
                    "low", "Identity", "SSH root key login remains permitted",
                    f"PermitRootLogin is {root_login}; passwords are blocked but root keys can still authenticate.",
                    "Consider a named administrative account with sudo, then disable direct root login.",
                    "ssh-root-key-login", 3,
                )
        else:
            add(
                "medium", "Identity", "Effective SSH configuration could not be audited",
                str(sshd.get("detail") or "sshd -T did not return usable settings."),
                "Run sudo sshd -T and correct any configuration errors.",
                "sshd-audit-unavailable", 5,
            )

        ssh = security.get("ssh", {})
        failed = int(ssh.get("failed_total", 0))
        if failed >= self.config.failed_ssh_warn:
            severity = "high" if failed >= self.config.failed_ssh_warn * 5 else "medium"
            add(
                severity, "Identity", "Elevated SSH authentication failures",
                f"{failed} failed SSH attempts were recorded during the last 15 minutes.",
                "Confirm the Cloud Firewall source restriction and investigate the top source addresses.",
                "ssh-failures", 12 if severity == "high" else 6,
            )

        for service in security.get("services", []):
            if not service.get("active"):
                add(
                    "high", "Availability", f"Service {service.get('name')} is not active",
                    f"systemd reports {service.get('state', 'unknown')}.",
                    f"Review journalctl -u {service.get('name')} and restore the service.",
                    f"service-{service.get('name')}", 12,
                )

        failed_units = security.get("failed_units", [])
        if failed_units:
            add(
                "medium", "Host", "systemd has failed units",
                ", ".join(failed_units[:8]),
                "Review systemctl --failed and repair or intentionally mask obsolete units.",
                "systemd-failed-units", 7,
            )

        pending = int(security.get("pending_updates", 0))
        if pending:
            add(
                "medium" if pending >= 10 else "low", "Host", "Ubuntu updates are pending",
                f"{pending} package updates are currently available.",
                "Review and apply updates, then reboot if required.",
                "pending-updates", 7 if pending >= 10 else 3,
            )
        if security.get("reboot_required"):
            add(
                "medium", "Host", "A reboot is required",
                "Ubuntu created /var/run/reboot-required after an update.",
                "Schedule a controlled reboot and verify WireGuard, Caddy, and EdgeWatch return automatically.",
                "reboot-required", 5,
            )
        if not security.get("automatic_updates", {}).get("ok"):
            add(
                "low", "Host", "Automatic upgrade timer is not healthy",
                "apt-daily-upgrade.timer is not both enabled and active.",
                "Enable the timer or maintain a documented manual patch cadence.",
                "automatic-updates", 3,
            )
        if not security.get("apparmor", {}).get("active"):
            add(
                "low", "Host", "AppArmor is not active",
                "The Ubuntu mandatory access control service is not active.",
                "Enable AppArmor unless a documented compatibility constraint prevents it.",
                "apparmor-inactive", 3,
            )
        if not security.get("time_sync", {}).get("synchronized"):
            add(
                "medium", "Host", "System time is not synchronized",
                "timedatectl does not report NTP synchronization. Accurate time is required for TLS, logs, and incident timelines.",
                "Restore systemd-timesyncd or the configured NTP client and verify synchronization.",
                "time-not-synchronized", 5,
            )
        journal = security.get(
            "service_journal",
            {},
        )

        warning_count = int(
            journal.get("warning_count", 0)
        )

        if warning_count:
            samples = journal.get("samples", [])
            journal_detail = (
                f"{warning_count} warning-or-higher "
                "messages were recorded for monitored "
                "edge services in the last 15 minutes."
            )

            sample_blocks: list[str] = []

            for sample in samples:
                if not isinstance(sample, dict):
                    continue

                service = str(
                    sample.get("service")
                    or "unknown"
                )

                timestamp = str(
                    sample.get("timestamp")
                    or "unknown"
                )

                message = str(
                    sample.get("message")
                    or "No message was recorded."
                )

                sample_blocks.append(
                    "\n".join(
                        [
                            f"Service: {service}",
                            f"Timestamp: {timestamp}",
                            f"Message: {message}",
                        ]
                    )
                )

            if sample_blocks:
                journal_detail += (
                    "\n\nJournal samples:\n"
                    + "\n\n".join(sample_blocks)
                )

            add(
                "medium",
                "Edge services",
                "Recent service warnings detected",
                journal_detail,
                (
                    "Review the listed service journal "
                    "messages and the full journal before "
                    "they become outages."
                ),
                "service-journal-warnings",
                min(
                    8,
                    4 + warning_count // 5,
                ),
            )

        unsafe_kernel = [item for item in security.get("kernel", {}).get("controls", []) if not item.get("ok")]
        if unsafe_kernel:
            add(
                "low", "Host", "Network kernel hardening differs from baseline",
                "; ".join(f"{item.get('name')}={item.get('value')}" for item in unsafe_kernel),
                "Review each sysctl against your WireGuard routing requirements before changing it.",
                "kernel-network-hardening", min(6, len(unsafe_kernel) * 2),
            )

        for check in urls:
            if not check.get("ok"):
                add(
                    "high", "Edge services", f"Endpoint check failed: {check.get('name')}",
                    f"{check.get('status')}: {check.get('detail', 'unreachable')}.",
                    "Check Caddy, DNS, WireGuard routing, the target service, and recent logs.",
                    f"url-{check.get('name')}", 10,
                )
            certificate = check.get("certificate") or {}
            days = certificate.get("days_remaining") if isinstance(certificate, dict) else None
            if days is not None and float(days) < 0:
                add(
                    "critical", "Edge services", f"TLS certificate expired: {check.get('name')}",
                    f"Certificate expiry was {certificate.get('expires_at')}.",
                    "Restore automatic certificate renewal and reload Caddy.",
                    f"tls-expired-{check.get('name')}", 22,
                )
            elif days is not None and float(days) <= int(check.get("certificate_warn_days", self.config.tls_warn_days)):
                severity = "high" if float(days) <= 7 else "medium"
                add(
                    severity, "Edge services", f"TLS certificate expires soon: {check.get('name')}",
                    f"Approximately {float(days):.1f} days remain.",
                    "Confirm Caddy can complete ACME renewal and that DNS still points to this VPS.",
                    f"tls-expiring-{check.get('name')}", 10 if severity == "high" else 5,
                )

        for row in dns_alignment:
            if not row.get("matches_interface"):
                add(
                    "high", "Edge services", f"DNS does not match this VPS: {row.get('hostname')}",
                    f"Resolved addresses: {', '.join(row.get('addresses') or []) or 'none'}.",
                    "Correct the DNS record or remove the hostname from expected_public_hostnames.",
                    f"dns-mismatch-{row.get('hostname')}", 12,
                )

        offline_peers = [peer for peer in wireguard if not peer.get("online")]
        for peer in offline_peers:
            add(
                "high", "Tunnel", f"WireGuard peer offline: {peer.get('name')}",
                f"Last handshake: {peer.get('latest_handshake') or 'never'}.",
                "Verify the home peer service, Internet access, tunnel configuration, and keepalive.",
                f"wg-{peer.get('name')}", 10,
            )

        for server in plex.get("servers", []):
            if server.get("configured") and not server.get("ok"):
                add(
                    "medium", "Plex", f"Plex telemetry unavailable: {server.get('name')}",
                    f"Status {server.get('status')}: {server.get('detail', 'request failed')}.",
                    "Verify the local tunnel URL, Plex token, and server availability.",
                    f"plex-{server.get('name')}", 6,
                )
            elif not server.get("configured"):
                add(
                    "low", "Visibility", f"Plex token missing: {server.get('name')}",
                    "The server can be health-checked, but active streams cannot be read without its token.",
                    "Add the matching token to /etc/edgewatch/secrets.toml with mode 600.",
                    f"plex-token-{server.get('name')}", 0,
                )

        if float(system.get("disk_percent", 0)) >= self.config.disk_warn_percent:
            add(
                "high", "Capacity", "Root filesystem usage is high",
                f"Disk utilization is {system.get('disk_percent')}%.",
                "Identify growth before writes fail, then clean or expand storage.",
                "disk-capacity", 10,
            )
        if float(system.get("inode_percent", 0)) >= self.config.inode_warn_percent:
            add(
                "high", "Capacity", "Root filesystem inode usage is high",
                f"Inode utilization is {system.get('inode_percent')}%.",
                "Find directories with excessive small files before inode exhaustion.",
                "inode-capacity", 10,
            )
        if float(system.get("memory_percent", 0)) >= self.config.memory_warn_percent:
            add(
                "medium", "Capacity", "Memory pressure is high",
                f"Memory utilization is {system.get('memory_percent')}%.",
                "Review top processes and sustained history before changing capacity.",
                "memory-pressure", 6,
            )
        if int(network.get("errors_delta", 0)) or int(network.get("drops_delta", 0)):
            add(
                "medium", "Network", "Interface errors or drops increased",
                f"Errors +{network.get('errors_delta', 0)}, drops +{network.get('drops_delta', 0)} in the current sample.",
                "Inspect ethtool statistics, host load, provider events, and packet queues.",
                "network-errors-drops", 5,
            )
        if int(network.get("connections", {}).get("established", 0)) >= self.config.connection_warn:
            add(
                "medium", "Network", "Established connection count is elevated",
                f"{network.get('connections', {}).get('established')} TCP connections are established.",
                "Review the connection map and processes for an expected traffic event.",
                "connection-count", 5,
            )

        if not geoip_status.get("city_available"):
            add(
                "low", "Visibility", "Local GeoIP database is not installed",
                "Connection IPs are visible, but map placement and country context are unavailable.",
                "Install GeoLite2 City and ASN databases using geoipupdate; no connection IPs are sent to a third party.",
                "geoip-missing", 0,
            )
        elif any(item.get("stale") for item in geoip_status.get("files", [])):
            add(
                "low", "Visibility", "GeoIP database may be stale",
                "At least one local MaxMind database is older than the configured freshness threshold.",
                "Run geoipupdate and confirm its scheduled timer succeeds.",
                "geoip-stale", 1,
            )

        score = min(100, sum(int(item["score"]) for item in insights))
        if score >= 70:
            level, headline = "critical", "Immediate review required"
        elif score >= 40:
            level, headline = "high", "Material security issues detected"
        elif score >= 20:
            level, headline = "guarded", "Several items need attention"
        elif score > 0:
            level, headline = "low", "EdgeWatch is healthy with minor findings"
        else:
            level, headline = "minimal", "No active risk findings"

        categories = [
            {"name": name, "score": min(100, category_score.get(name, 0))}
            for name in ("Exposure", "Identity", "Host", "Edge services", "Tunnel", "Plex", "Network", "Capacity", "Visibility")
        ]
        active_count = sum(1 for item in insights if item.get("score", 0) > 0)
        return {
            "risk_score": score,
            "risk_level": level,
            "headline": headline,
            "detail": f"{active_count} active finding{'s' if active_count != 1 else ''} · {len(insights) - active_count} visibility notice{'s' if len(insights) - active_count != 1 else ''}.",
            "active_findings": active_count,
            "categories": categories,
            "insights": sorted(
                insights,
                key=lambda item: ({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(item["severity"]), 0), int(item["score"])),
                reverse=True,
            ),
            "coverage": {
                "host_firewall": bool(firewall.get("available") or firewall.get("active")),
                "cloud_firewall": bool(linode.get("configured") and linode.get("attached")),
                "ssh_configuration": bool(sshd.get("available")),
                "tls_expiry": any(check.get("certificate") for check in urls),
                "service_health": bool(security.get("services")),
                "wireguard": bool(self.config.wireguard_interfaces),
                "plex_sessions": bool(self.config.plex_servers),
                "connection_geolocation": bool(geoip_status.get("city_available")),
                "push_notifications": self.config.notifications.enabled,
                "limitations": [
                    "No packet payload inspection or application-layer intrusion detection",
                    "No filesystem integrity monitoring or malware scanner",
                    "No external port scan unless a separate remote probe is added",
                    "GeoIP indicates an approximate network location, never a physical address",
                ],
            },
        }

    def collect(self) -> tuple[dict[str, object], dict[str, int | float | str]]:
        now = datetime.now(timezone.utc)
        now_epoch = int(now.timestamp())
        now_monotonic = time.monotonic()

        current_cpu = parse_proc_stat_cpu(_read_text("/proc/stat"))
        cpu = cpu_percent(self.previous_cpu, current_cpu)
        self.previous_cpu = current_cpu

        meminfo = parse_meminfo(_read_text("/proc/meminfo"))
        memory = memory_percent(meminfo)
        disk = shutil.disk_usage("/")
        disk_percent = round(disk.used * 100 / disk.total, 1) if disk.total else 0.0
        inode = os.statvfs("/")
        inode_total = inode.f_files
        inode_used = inode_total - inode.f_ffree
        inode_percent = round(inode_used * 100 / inode_total, 1) if inode_total else 0.0
        load1, load5, load15 = os.getloadavg()
        uptime_seconds = int(float(_read_text("/proc/uptime").split()[0]))

        counters = _network_counters(self.config.primary_interface)
        if counters is None:
            raise RuntimeError(f"Network interface {self.config.primary_interface} was not found")
        previous = self.previous_network.get(self.config.primary_interface)
        elapsed = (
            max(0.001, now_monotonic - self.previous_sample_monotonic)
            if self.previous_sample_monotonic is not None
            else float(self.config.sample_interval_seconds)
        )
        rx_delta = max(0, counters.rx_bytes - previous[0]) if previous else 0
        tx_delta = max(0, counters.tx_bytes - previous[1]) if previous else 0
        rx_rate = rx_delta / elapsed
        tx_rate = tx_delta / elapsed
        previous_error_drop = getattr(self, "_previous_error_drop", None)
        errors_total = counters.rx_errors + counters.tx_errors
        drops_total = counters.rx_drops + counters.tx_drops
        errors_delta = max(0, errors_total - previous_error_drop[0]) if previous_error_drop else 0
        drops_delta = max(0, drops_total - previous_error_drop[1]) if previous_error_drop else 0
        self._previous_error_drop = (errors_total, drops_total)
        self.previous_network[self.config.primary_interface] = (counters.rx_bytes, counters.tx_bytes)
        self.previous_sample_monotonic = now_monotonic

        if now_monotonic - self.last_security_at >= self.config.security_interval_seconds or not self.last_security:
            self.last_security = self._security_snapshot()
            self.last_security_at = now_monotonic
        security = self.last_security
        listeners = security.get("listeners", [])

        connections = self._connections(listeners, now_epoch)
        network = {
            "interface": self.config.primary_interface,
            "rx_bytes_total": counters.rx_bytes,
            "tx_bytes_total": counters.tx_bytes,
            "rx_rate_bps": round(rx_rate, 2),
            "tx_rate_bps": round(tx_rate, 2),
            "rx_rate": _fmt_rate(rx_rate),
            "tx_rate": _fmt_rate(tx_rate),
            "errors_total": errors_total,
            "drops_total": drops_total,
            "errors_delta": errors_delta,
            "drops_delta": drops_delta,
            "connections": connections,
            "monthly_transfer_limit_bytes": int(self.config.monthly_transfer_gb * 1024**3),
            "month": now.strftime("%Y-%m"),
        }

        with ThreadPoolExecutor(max_workers=2) as executor:
            wireguard_future = executor.submit(self._wireguard, now_epoch)
            plex_future = executor.submit(self._plex)
            wireguard = wireguard_future.result()
            plex = plex_future.result()

        if now_monotonic - self.last_url_checks_at >= self.config.security_interval_seconds or not self.last_url_checks:
            self.last_url_checks = self._url_checks()
            self.last_url_checks_at = now_monotonic
        url_checks = self.last_url_checks
        linode = self._linode_firewall()
        linode_transfer = self._linode_transfer()

        if linode_transfer.get("ok"):
            used_gb = float(
                linode_transfer.get("used_gb") or 0.0
            )
            quota_gb = float(
                linode_transfer.get("quota_gb") or 0.0
            )
            billable_gb = float(
                linode_transfer.get("billable_gb") or 0.0
            )

            network.update(
                {
                    "monthly_transfer_used_gb": used_gb,
                    "monthly_transfer_quota_gb": quota_gb,
                    "monthly_transfer_billable_gb": billable_gb,
                    "monthly_transfer_used_bytes": int(
                        used_gb * 1_000_000_000
                    ),
                    "monthly_transfer_limit_bytes": int(
                        quota_gb * 1_000_000_000
                    ),
                    "monthly_transfer_source": "linode_account_api",
                    "monthly_transfer_api_status": "available",
                }
            )
        else:
            network.update(
                {
                    "monthly_transfer_source": "local_estimate",
                    "monthly_transfer_api_status": str(
                        linode_transfer.get("status")
                        or "unavailable"
                    ),
                }
            )

        geoip_status = self.geoip.status()
        dns_alignment = self._dns_alignment(connections.get("public_interface_ips", []))

        system = {
            "hostname": platform.node(),
            "kernel": platform.release(),
            "os": platform.platform(),
            "boot_id": self.boot_id,
            "uptime_seconds": uptime_seconds,
            "cpu_percent": cpu,
            "memory_percent": memory,
            "memory_total_bytes": meminfo.get("MemTotal", 0),
            "memory_available_bytes": meminfo.get("MemAvailable", 0),
            "disk_percent": disk_percent,
            "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free,
            "inode_percent": inode_percent,
            "load1": round(load1, 2),
            "load5": round(load5, 2),
            "load15": round(load15, 2),
        }

        posture = self._risk_and_insights(
            system, security, network, wireguard, url_checks, plex, linode, geoip_status, dns_alignment
        )
        snapshot: dict[str, object] = {
            "version": "0.5.4",
            "generated_at": now.isoformat(),
            "generated_epoch": now_epoch,
            "display_timezone": self.config.timezone,
            "system": system,
            "network": network,
            "security": security,
            "wireguard": wireguard,
            "url_checks": url_checks,
            "plex": plex,
            "linode_firewall": linode,
            "linode_transfer": linode_transfer,
            "geoip": geoip_status,
            "dns_alignment": dns_alignment,
            "posture": posture,
            "notifications": {
                "enabled": self.config.notifications.enabled,
                "provider": self.config.notifications.provider,
                "configured": self.config.notifications.enabled and bool(self.secrets.ntfy.url),
                "minimum_severity": self.config.notifications.minimum_severity,
            },
            "topology": {
                "wireguard_interface": (
                    self.config.wireguard_interfaces[0]
                    if self.config.wireguard_interfaces
                    else ""
                ),
                "services": [
                    {
                        "name": service.name,
                        "eyebrow": service.eyebrow,
                        "peer_name": service.peer_name,
                        "check_names": list(service.check_names),
                        "path": service.path,
                        "link_label": service.link_label,
                    }
                    for service in self.config.topology_services
                ],
            },
        }

        local_day = now.astimezone(ZoneInfo(self.config.timezone)).date().isoformat()
        sample: dict[str, int | float | str] = {
            "ts": now_epoch,
            "day": local_day,
            "interface": self.config.primary_interface,
            "cpu_percent": cpu,
            "memory_percent": memory,
            "disk_percent": disk_percent,
            "load1": round(load1, 2),
            "rx_bps": round(rx_rate, 2),
            "tx_bps": round(tx_rate, 2),
            "rx_bytes": rx_delta,
            "tx_bytes": tx_delta,
            "established_connections": int(connections.get("established", 0)),
            "failed_ssh": int(security.get("ssh", {}).get("failed_total", 0)),
            "risk_score": int(posture["risk_score"]),
            "plex_streams": int(plex.get("active_streams", 0)),
            "public_peers": int(connections.get("public_peer_count", 0)),
            "active_findings": int(posture.get("active_findings", 0)),
        }
        return snapshot, sample


def event_from_insight(insight: dict[str, object], now_epoch: int) -> dict[str, object]:
    fingerprint = str(insight.get("fingerprint") or hashlib.sha256(
        f"{insight.get('category')}|{insight.get('title')}".encode()
    ).hexdigest()[:20])
    return {
        "ts": now_epoch,
        "severity": str(insight.get("severity") or "info"),
        "category": str(insight.get("category") or "General"),
        "title": str(insight.get("title") or "Finding"),
        "detail": str(insight.get("detail") or ""),
        "fingerprint": fingerprint,
    }

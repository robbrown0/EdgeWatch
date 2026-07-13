from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 on Ubuntu 22.04
    import tomli as tomllib


@dataclass(frozen=True)
class URLCheck:
    name: str
    url: str
    timeout_seconds: float = 4.0
    tls_verify: bool = True
    expected_status_min: int = 200
    expected_status_max: int = 499
    certificate_warn_days: int = 21


@dataclass(frozen=True)
class PeerAlias:
    name: str
    allowed_ip: str
    scope: str = "any"


@dataclass(frozen=True)
class CaddyActivitySource:
    name: str
    log_path: Path
    hosts: tuple[str, ...] = field(default_factory=tuple)
    kind: str = "https"
    label: str = "HTTPS request"


@dataclass(frozen=True)
class TopologyService:
    name: str
    eyebrow: str = "SERVICE"
    peer_name: str = ""
    check_names: tuple[str, ...] = field(default_factory=tuple)
    path: str = "wireguard"
    link_label: str = "TCP"


@dataclass(frozen=True)
class PlexServer:
    name: str
    url: str
    timeout_seconds: float = 4.0
    tls_verify: bool = True


@dataclass(frozen=True)
class GeoIPConfig:
    city_database_path: Path = Path("/var/lib/GeoIP/GeoLite2-City.mmdb")
    asn_database_path: Path = Path("/var/lib/GeoIP/GeoLite2-ASN.mmdb")
    warn_age_days: int = 28


@dataclass(frozen=True)
class LinodeConfig:
    enabled: bool = False
    linode_id: int = 0
    firewall_id: int = 0
    check_interval_seconds: int = 300
    require_inbound_drop: bool = True


@dataclass(frozen=True)
class NotificationConfig:
    enabled: bool = False
    provider: str = "ntfy"
    minimum_severity: str = "high"
    cooldown_seconds: int = 900
    recovery_notifications: bool = True
    dashboard_url: str = ""


@dataclass(frozen=True)
class IdentityConfig:
    provider: str = "Microsoft Entra ID"
    directory_name: str = ""
    tenant_id: str = ""
    application_name: str = "EdgeWatch"
    client_id: str = ""
    access_label: str = "Assigned enterprise application user"
    session_lifetime: str = ""
    session_refresh: str = ""


@dataclass(frozen=True)
class AppConfig:
    version: str = "0.5.5"
    sample_interval_seconds: int = 3
    history_interval_seconds: int = 10
    security_interval_seconds: int = 30
    maintenance_interval_seconds: int = 900
    retention_days: int = 14
    history_points_max: int = 2880
    primary_interface: str = "eth0"
    monthly_transfer_gb: float = 2000.0
    timezone: str = "America/New_York"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8765
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")
    data_dir: Path = Path("/var/lib/edgewatch")
    runtime_dir: Path = Path("/run/edgewatch")
    secrets_path: Path = Path("/etc/edgewatch/secrets.toml")
    site_config_path: Path = Path("/etc/edgewatch/site.toml")
    services: tuple[str, ...] = ("caddy", "wg-quick@wg0", "ssh")
    wireguard_interfaces: tuple[str, ...] = ("wg0",)
    peer_stale_seconds: int = 180
    flow_recent_seconds: int = 60
    allowed_public_tcp_ports: frozenset[int] = frozenset({22, 80, 443})
    allowed_public_udp_ports: frozenset[int] = frozenset({443, 51820})
    failed_ssh_warn: int = 10
    connection_warn: int = 250
    disk_warn_percent: float = 85.0
    inode_warn_percent: float = 85.0
    memory_warn_percent: float = 90.0
    tls_warn_days: int = 21
    expected_public_hostnames: tuple[str, ...] = field(default_factory=tuple)
    url_checks: tuple[URLCheck, ...] = field(default_factory=tuple)
    peer_aliases: tuple[PeerAlias, ...] = field(default_factory=tuple)
    plex_servers: tuple[PlexServer, ...] = field(default_factory=tuple)
    service_port_names: tuple[tuple[int, str], ...] = field(default_factory=tuple)
    caddy_activity_sources: tuple[CaddyActivitySource, ...] = field(default_factory=tuple)
    topology_services: tuple[TopologyService, ...] = field(default_factory=tuple)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)
    linode: LinodeConfig = field(default_factory=LinodeConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)

    @property
    def database_path(self) -> Path:
        return self.data_dir / "edgewatch.db"

    @property
    def snapshot_path(self) -> Path:
        return self.runtime_dir / "latest.json"


@dataclass(frozen=True)
class PlexToken:
    name: str
    token: str


@dataclass(frozen=True)
class NtfySecret:
    url: str = ""
    token: str = ""


@dataclass(frozen=True)
class Secrets:
    default_plex_token: str = ""
    plex_tokens: tuple[PlexToken, ...] = field(default_factory=tuple)
    ntfy: NtfySecret = field(default_factory=NtfySecret)
    linode_api_token: str = ""

    def plex_token_for(self, name: str) -> str:
        for item in self.plex_tokens:
            if item.name == name:
                return item.token
        return self.default_plex_token


def _tuple_of_strings(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Expected a list of strings")
    return tuple(item.strip() for item in value if item.strip())


def _port_set(value: Any, default: frozenset[int]) -> frozenset[int]:
    if value is None:
        return default
    if not isinstance(value, list):
        raise ValueError("Expected a list of ports")
    ports: set[int] = set()
    for item in value:
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")
        ports.add(port)
    return frozenset(ports)


def _https_or_http_url(value: str, field_name: str) -> str:
    url = value.strip()
    if url and not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"{field_name} must begin with http:// or https://")
    return url.rstrip("/")


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_raw_config(config_path: Path) -> tuple[dict[str, Any], Path]:
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)

    app = raw.get("app", {})
    configured_site_path = str(app.get("site_config_path", "")).strip()
    if configured_site_path:
        site_path = Path(configured_site_path)
        if not site_path.is_absolute():
            site_path = config_path.parent / site_path
    else:
        site_path = config_path.with_name("site.toml")

    if site_path.exists():
        with site_path.open("rb") as handle:
            site_raw = tomllib.load(handle)
        raw = _deep_merge(raw, site_raw)

    return raw, site_path


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    raw, site_config_path = _load_raw_config(config_path)

    app = raw.get("app", {})
    monitoring = raw.get("monitoring", {})
    security = raw.get("security", {})
    web = raw.get("web", {})
    geoip_raw = raw.get("geoip", {})
    linode_raw = raw.get("linode", {})
    notifications_raw = raw.get("notifications", {})
    identity_raw = raw.get("identity", {})

    checks: list[URLCheck] = []
    for item in raw.get("url_checks", []):
        checks.append(
            URLCheck(
                name=str(item["name"]).strip(),
                url=_https_or_http_url(str(item["url"]), "url_checks.url"),
                timeout_seconds=max(0.5, float(item.get("timeout_seconds", 4.0))),
                tls_verify=bool(item.get("tls_verify", True)),
                expected_status_min=int(item.get("expected_status_min", 200)),
                expected_status_max=int(item.get("expected_status_max", 499)),
                certificate_warn_days=max(1, int(item.get("certificate_warn_days", security.get("tls_warn_days", 21)))),
            )
        )

    aliases: list[PeerAlias] = []
    for item in raw.get("peer_aliases", []):
        scope = str(item.get("scope", "any")).strip().lower()
        if scope not in {"any", "public", "private", "wireguard"}:
            raise ValueError(f"Invalid peer alias scope: {scope}")
        aliases.append(
            PeerAlias(
                name=str(item["name"]).strip(),
                allowed_ip=str(item["allowed_ip"]).strip(),
                scope=scope,
            )
        )

    plex_servers: list[PlexServer] = []
    for item in raw.get("plex_servers", []):
        plex_servers.append(
            PlexServer(
                name=str(item["name"]).strip(),
                url=_https_or_http_url(str(item["url"]), "plex_servers.url"),
                timeout_seconds=max(0.5, float(item.get("timeout_seconds", 4.0))),
                tls_verify=bool(item.get("tls_verify", True)),
            )
        )

    service_port_names: list[tuple[int, str]] = []
    for port_text, label in raw.get("service_ports", {}).items():
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid service port: {port}")
        clean_label = str(label).strip()
        if clean_label:
            service_port_names.append((port, clean_label[:120]))

    caddy_activity_sources: list[CaddyActivitySource] = []
    for item in raw.get("caddy_activity_sources", []):
        hosts = _tuple_of_strings(item.get("hosts"), tuple())
        caddy_activity_sources.append(
            CaddyActivitySource(
                name=str(item["name"]).strip()[:160],
                log_path=Path(str(item["log_path"])),
                hosts=tuple(host.lower() for host in hosts),
                kind=str(item.get("kind", "https")).strip().lower()[:80] or "https",
                label=str(item.get("label", "HTTPS request")).strip()[:160] or "HTTPS request",
            )
        )

    topology_services: list[TopologyService] = []
    for item in raw.get("topology_services", []):
        path_name = str(item.get("path", "wireguard")).strip().lower()
        if path_name not in {"wireguard", "edge"}:
            raise ValueError(f"Invalid topology service path: {path_name}")
        topology_services.append(
            TopologyService(
                name=str(item["name"]).strip()[:160],
                eyebrow=str(item.get("eyebrow", "SERVICE")).strip()[:80] or "SERVICE",
                peer_name=str(item.get("peer_name", "")).strip()[:160],
                check_names=_tuple_of_strings(item.get("check_names"), tuple()),
                path=path_name,
                link_label=str(item.get("link_label", "TCP")).strip()[:80] or "TCP",
            )
        )

    data_dir = Path(str(app.get("data_dir", "/var/lib/edgewatch")))
    runtime_dir = Path(str(app.get("runtime_dir", "/run/edgewatch")))
    secrets_path = Path(str(app.get("secrets_path", "/etc/edgewatch/secrets.toml")))

    return AppConfig(
        sample_interval_seconds=max(2, int(app.get("sample_interval_seconds", 3))),
        history_interval_seconds=max(5, int(app.get("history_interval_seconds", 10))),
        security_interval_seconds=max(10, int(app.get("security_interval_seconds", 30))),
        maintenance_interval_seconds=max(300, int(app.get("maintenance_interval_seconds", 900))),
        retention_days=max(1, int(app.get("retention_days", 14))),
        history_points_max=max(120, int(app.get("history_points_max", 2880))),
        primary_interface=str(monitoring.get("primary_interface", "eth0")).strip(),
        monthly_transfer_gb=max(1.0, float(monitoring.get("monthly_transfer_gb", 2000.0))),
        timezone=str(app.get("timezone", "America/New_York")).strip(),
        bind_host=str(web.get("bind_host", "127.0.0.1")).strip(),
        bind_port=int(web.get("bind_port", 8765)),
        allowed_hosts=_tuple_of_strings(web.get("allowed_hosts"), ("localhost", "127.0.0.1")),
        data_dir=data_dir,
        runtime_dir=runtime_dir,
        secrets_path=secrets_path,
        site_config_path=site_config_path,
        services=_tuple_of_strings(monitoring.get("services"), ("caddy", "wg-quick@wg0", "ssh")),
        wireguard_interfaces=_tuple_of_strings(monitoring.get("wireguard_interfaces"), ("wg0",)),
        peer_stale_seconds=max(30, int(monitoring.get("peer_stale_seconds", 180))),
        flow_recent_seconds=max(15, min(600, int(monitoring.get("flow_recent_seconds", 60)))),
        allowed_public_tcp_ports=_port_set(security.get("allowed_public_tcp_ports"), frozenset({22, 80, 443})),
        allowed_public_udp_ports=_port_set(security.get("allowed_public_udp_ports"), frozenset({443, 51820})),
        failed_ssh_warn=max(1, int(security.get("failed_ssh_warn", 10))),
        connection_warn=max(10, int(security.get("connection_warn", 250))),
        disk_warn_percent=float(security.get("disk_warn_percent", 85.0)),
        inode_warn_percent=float(security.get("inode_warn_percent", 85.0)),
        memory_warn_percent=float(security.get("memory_warn_percent", 90.0)),
        tls_warn_days=max(1, int(security.get("tls_warn_days", 21))),
        expected_public_hostnames=_tuple_of_strings(monitoring.get("expected_public_hostnames"), tuple()),
        url_checks=tuple(checks),
        peer_aliases=tuple(aliases),
        plex_servers=tuple(plex_servers),
        service_port_names=tuple(sorted(service_port_names)),
        caddy_activity_sources=tuple(caddy_activity_sources),
        topology_services=tuple(topology_services),
        geoip=GeoIPConfig(
            city_database_path=Path(str(geoip_raw.get("city_database_path", "/var/lib/GeoIP/GeoLite2-City.mmdb"))),
            asn_database_path=Path(str(geoip_raw.get("asn_database_path", "/var/lib/GeoIP/GeoLite2-ASN.mmdb"))),
            warn_age_days=max(1, int(geoip_raw.get("warn_age_days", 28))),
        ),
        linode=LinodeConfig(
            enabled=bool(linode_raw.get("enabled", False)),
            linode_id=max(0, int(linode_raw.get("linode_id", 0))),
            firewall_id=max(0, int(linode_raw.get("firewall_id", 0))),
            check_interval_seconds=max(60, int(linode_raw.get("check_interval_seconds", 300))),
            require_inbound_drop=bool(linode_raw.get("require_inbound_drop", True)),
        ),
        notifications=NotificationConfig(
            enabled=bool(notifications_raw.get("enabled", False)),
            provider=str(notifications_raw.get("provider", "ntfy")).strip().lower(),
            minimum_severity=str(notifications_raw.get("minimum_severity", "high")).strip().lower(),
            cooldown_seconds=max(60, int(notifications_raw.get("cooldown_seconds", 900))),
            recovery_notifications=bool(notifications_raw.get("recovery_notifications", True)),
            dashboard_url=str(notifications_raw.get("dashboard_url", "")).strip(),
        ),
        identity=IdentityConfig(
            provider=str(identity_raw.get("provider", "Microsoft Entra ID")).strip()[:120],
            directory_name=str(identity_raw.get("directory_name", "")).strip()[:200],
            tenant_id=str(identity_raw.get("tenant_id", "")).strip()[:200],
            application_name=str(identity_raw.get("application_name", "EdgeWatch")).strip()[:200],
            client_id=str(identity_raw.get("client_id", "")).strip()[:200],
            access_label=str(identity_raw.get("access_label", "Assigned enterprise application user")).strip()[:240],
            session_lifetime=str(identity_raw.get("session_lifetime", "")).strip()[:120],
            session_refresh=str(identity_raw.get("session_refresh", "")).strip()[:120],
        ),
    )


def load_secrets(path: str | Path) -> Secrets:
    secrets_path = Path(path)
    if not secrets_path.exists():
        return Secrets()
    with secrets_path.open("rb") as handle:
        raw = tomllib.load(handle)

    tokens: list[PlexToken] = []
    for item in raw.get("plex_tokens", []):
        name = str(item.get("name", "")).strip()
        token = str(item.get("token", "")).strip()
        if name and token:
            tokens.append(PlexToken(name=name, token=token))

    ntfy_raw = raw.get("ntfy", {})
    linode_raw = raw.get("linode", {})
    plex_raw = raw.get("plex", {})
    return Secrets(
        default_plex_token=str(plex_raw.get("token", "")).strip(),
        plex_tokens=tuple(tokens),
        ntfy=NtfySecret(
            url=_https_or_http_url(str(ntfy_raw.get("url", "")), "ntfy.url"),
            token=str(ntfy_raw.get("token", "")).strip(),
        ),
        linode_api_token=str(linode_raw.get("api_token", "")).strip(),
    )

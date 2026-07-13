from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgewatch.collector import Collector
from edgewatch.config import AppConfig, CaddyActivitySource, PeerAlias, load_config


class FakeGeoIP:
    def lookup(self, _ip: str) -> dict[str, object]:
        return {"located": False}

    def status(self) -> dict[str, object]:
        return {"city_available": False, "asn_available": False, "files": []}

    def close(self) -> None:
        return None


class SiteConfigTests(unittest.TestCase):
    def test_private_site_overlay_replaces_environment_sections(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_path = root / "config.toml"
            site_path = root / "site.toml"

            config_path.write_text(
                """
[app]
timezone = "UTC"
[web]
allowed_hosts = ["localhost"]
[monitoring]
expected_public_hostnames = []
[notifications]
dashboard_url = ""
""",
                encoding="utf-8",
            )
            site_path.write_text(
                """
[web]
allowed_hosts = ["monitor.example.com", "localhost"]
[monitoring]
expected_public_hostnames = ["monitor.example.com"]
[notifications]
dashboard_url = "https://monitor.example.com"
[service_ports]
"5055" = "Request service"
[[peer_aliases]]
name = "Known Remote Service"
allowed_ip = "198.51.100.54/32"
scope = "public"
[[caddy_activity_sources]]
name = "Dashboard"
log_path = "/var/log/caddy/dashboard-access.log"
hosts = ["monitor.example.com"]
kind = "edgewatch"
label = "EdgeWatch dashboard"
[[topology_services]]
name = "Media Node A"
eyebrow = "MEDIA BACKEND"
peer_name = "Media Node A"
check_names = ["Media Node A public"]
path = "wireguard"
link_label = "Plex"
""",
                encoding="utf-8",
            )

            config = load_config(config_path)

            self.assertEqual(config.site_config_path, site_path)
            self.assertEqual(
                config.allowed_hosts,
                ("monitor.example.com", "localhost"),
            )
            self.assertEqual(
                config.expected_public_hostnames,
                ("monitor.example.com",),
            )
            self.assertEqual(
                config.notifications.dashboard_url,
                "https://monitor.example.com",
            )
            self.assertEqual(config.service_port_names, ((5055, "Request service"),))
            self.assertEqual(config.peer_aliases[0].scope, "public")
            self.assertEqual(config.caddy_activity_sources[0].kind, "edgewatch")
            self.assertEqual(config.topology_services[0].name, "Media Node A")

    def test_public_alias_is_applied_only_to_observed_connections(self) -> None:
        current_ss = {
            "value": '0 0 203.0.113.10:443 198.51.100.54:50000 users:(("caddy",pid=10,fd=5))'
        }

        def runner(args: list[str], _timeout: float) -> tuple[int, str, str]:
            if args[:2] == ["ss", "-H"]:
                return 0, current_ss["value"], ""
            if args[:3] == ["ip", "-j", "address"]:
                return 0, json.dumps([{"addr_info": [{"local": "203.0.113.10"}]}]), ""
            return 0, "", ""

        config = AppConfig(
            flow_recent_seconds=30,
            peer_aliases=(
                PeerAlias(
                    name="Known Remote Service",
                    allowed_ip="198.51.100.54/32",
                    scope="public",
                ),
            ),
        )
        collector = Collector(config, command_runner=runner, geoip_resolver=FakeGeoIP())
        listeners = [{"protocol": "tcp", "port": 443, "public_bind": True}]

        with patch(
            "edgewatch.collector._is_public_ip",
            side_effect=lambda value: value in {"203.0.113.10", "198.51.100.54"},
        ):
            first = collector._connections(listeners, 1_000)
        self.assertEqual(first["public_peers"][0]["name"], "Known Remote Service")

        current_ss["value"] = ""
        with patch(
            "edgewatch.collector._is_public_ip",
            side_effect=lambda value: value in {"203.0.113.10", "198.51.100.54"},
        ):
            recent = collector._connections(listeners, 1_015)
        self.assertEqual(recent["recent_public_peers"][0]["name"], "Known Remote Service")

        with patch(
            "edgewatch.collector._is_public_ip",
            side_effect=lambda value: value in {"203.0.113.10", "198.51.100.54"},
        ):
            expired = collector._connections(listeners, 1_031)
        self.assertEqual(expired["recent_public_peers"], [])

    def test_caddy_activity_source_controls_host_classification(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "dashboard.log"
            log_path.write_text(
                json.dumps(
                    {
                        "ts": 1_000,
                        "request": {
                            "client_ip": "198.51.100.25",
                            "host": "monitor.example.com",
                            "method": "GET",
                            "uri": "/overview?token=must-not-leak",
                            "headers": {},
                        },
                        "status": 200,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            config = AppConfig(
                caddy_activity_sources=(
                    CaddyActivitySource(
                        name="Dashboard",
                        log_path=log_path,
                        hosts=("monitor.example.com",),
                        kind="edgewatch",
                        label="EdgeWatch dashboard",
                    ),
                ),
            )
            collector = Collector(config, geoip_resolver=FakeGeoIP())
            with patch(
                "edgewatch.collector._is_public_ip",
                side_effect=lambda value: value == "198.51.100.25",
            ):
                activity = collector._caddy_activity(1_005)

            self.assertEqual(activity["198.51.100.25"]["kind"], "edgewatch")
            self.assertEqual(activity["198.51.100.25"]["path"], "/overview")
            self.assertNotIn("token", str(activity))


if __name__ == "__main__":
    unittest.main()

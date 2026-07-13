from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from edgewatch.collector import Collector
from edgewatch.config import AppConfig, load_config


class FakeGeoIP:
    def lookup(self, _ip: str) -> dict[str, object]:
        return {"located": False}

    def status(self) -> dict[str, object]:
        return {"city_available": True, "asn_available": True, "files": []}

    def close(self) -> None:
        pass


class ConfigAndRiskTests(unittest.TestCase):
    def test_config_loads_command_center_sections(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.toml"
            path.write_text("""
[app]
sample_interval_seconds = 7
secrets_path = "/tmp/edgewatch-secrets.toml"
[web]
allowed_hosts = ["monitor.example.com"]
[monitoring]
primary_interface = "ens3"
flow_recent_seconds = 75
expected_public_hostnames = ["monitor.example.com"]
[security]
allowed_public_tcp_ports = [22, 443]
[notifications]
enabled = true
minimum_severity = "medium"
[identity]
provider = "Microsoft Entra ID"
directory_name = "Example Directory"
tenant_id = "11111111-2222-3333-4444-555555555555"
application_name = "EdgeWatch Production"
client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
session_lifetime = "8 hours"
session_refresh = "Every 1 hour"
[[plex_servers]]
name = "Media Node A"
url = "http://10.200.0.2:32400"
""")
            config = load_config(path)
            self.assertEqual(config.sample_interval_seconds, 7)
            self.assertEqual(config.primary_interface, "ens3")
            self.assertEqual(config.flow_recent_seconds, 75)
            self.assertEqual(config.allowed_hosts, ("monitor.example.com",))
            self.assertEqual(config.allowed_public_tcp_ports, frozenset({22, 443}))
            self.assertEqual(config.plex_servers[0].name, "Media Node A")
            self.assertTrue(config.notifications.enabled)
            self.assertEqual(config.identity.directory_name, "Example Directory")
            self.assertEqual(
                config.identity.tenant_id,
                "11111111-2222-3333-4444-555555555555",
            )
            self.assertEqual(
                config.identity.client_id,
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            )
            self.assertEqual(config.identity.session_lifetime, "8 hours")

    @staticmethod
    def clean_inputs() -> dict[str, object]:
        security = {
            "firewall": {"available": True, "active": True},
            "unexpected_listeners": [],
            "ssh": {"failed_total": 0},
            "sshd": {
                "available": True,
                "password_authentication": "no",
                "permit_root_login": "no",
            },
            "services": [{"name": "caddy", "active": True}],
            "failed_units": [],
            "pending_updates": 0,
            "reboot_required": False,
            "automatic_updates": {"ok": True},
            "apparmor": {"active": True},
            "time_sync": {"synchronized": True},
            "service_journal": {"warning_count": 0},
            "kernel": {"controls": []},
        }
        return {
            "system": {"disk_percent": 20, "inode_percent": 10, "memory_percent": 30},
            "security": security,
            "network": {"errors_delta": 0, "drops_delta": 0, "connections": {"established": 2}},
            "wireguard": [],
            "urls": [],
            "plex": {"servers": []},
            "linode": {"enabled": False, "configured": False, "ok": True},
            "geoip_status": {"city_available": True, "files": []},
            "dns_alignment": [],
        }

    def test_risk_engine_flags_exposure(self) -> None:
        collector = Collector(AppConfig(), geoip_resolver=FakeGeoIP())
        inputs = self.clean_inputs()
        inputs["security"]["unexpected_listeners"] = [{"protocol": "tcp", "port": 9000}]
        posture = collector._risk_and_insights(**inputs)
        self.assertGreaterEqual(posture["risk_score"], 20)
        self.assertEqual(posture["insights"][0]["category"], "Exposure")

    def test_clean_risk(self) -> None:
        collector = Collector(AppConfig(), geoip_resolver=FakeGeoIP())
        posture = collector._risk_and_insights(**self.clean_inputs())
        self.assertEqual(posture["risk_score"], 0)
        self.assertEqual(posture["risk_level"], "minimal")
        self.assertEqual(posture["active_findings"], 0)

    def test_low_risk_summary_uses_product_name_and_active_count(self) -> None:
        collector = Collector(AppConfig(), geoip_resolver=FakeGeoIP())
        inputs = self.clean_inputs()
        inputs["security"]["sshd"]["password_authentication"] = "yes"

        posture = collector._risk_and_insights(**inputs)

        self.assertEqual(posture["risk_level"], "low")
        self.assertEqual(
            posture["headline"],
            "EdgeWatch is healthy with minor findings",
        )
        self.assertEqual(
            posture["detail"],
            "1 active finding · 0 visibility notices.",
        )
        self.assertEqual(posture["active_findings"], 1)


if __name__ == "__main__":
    unittest.main()

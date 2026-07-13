from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edgewatch.collector import Collector
from edgewatch.config import AppConfig, GeoIPConfig, NotificationConfig, TopologyService
from edgewatch.parsers import NetworkCounters


class FakeGeoIP:
    def status(self):
        return {"city_available": False, "asn_available": False, "files": []}

    def close(self):
        return None


class ContractCollector(Collector):
    def _security_snapshot(self):
        return {
            "listeners": [],
            "unexpected_listeners": [],
            "services": [
                {"name": "caddy", "active": True, "state": "active"},
                {"name": "wg-quick@wg0", "active": True, "state": "active"},
                {"name": "ssh", "active": True, "state": "active"},
            ],
            "firewall": {"active": True, "status": "active"},
            "ssh": {"failed_total": 0, "successful_total": 1, "top_sources": []},
            "sshd": {
                "available": True,
                "password_authentication": "no",
                "permit_root_login": "no",
                "pubkey_authentication": "yes",
                "max_auth_tries": "3",
                "controls": [],
            },
            "failed_units": [],
            "pending_updates": 0,
            "reboot_required": False,
            "automatic_updates": {"ok": True, "enabled": True, "active": True},
            "apparmor": {"ok": True, "active": True},
            "fail2ban": {"ok": True, "installed": False, "active": False},
            "time_sync": {"ok": True, "synchronized": True},
            "kernel": {"ok": True, "controls": []},
            "service_journal": {"ok": True, "warning_count": 0, "samples": []},
        }

    def _connections(self, listeners, now_epoch):
        return {
            "established": 2,
            "public_peer_count": 1,
            "public_interface_ips": ["203.0.113.10"],
            "peers": [
                {
                    "ip": "198.51.100.20",
                    "remote_port": 443,
                    "local_port": 443,
                    "service": "HTTPS",
                    "process": "caddy",
                    "connections": 2,
                    "first_seen": now_epoch,
                    "last_seen": now_epoch,
                    "geo": None,
                }
            ],
            "top_processes": [{"name": "caddy", "connections": 2}],
            "by_service": [{"name": "HTTPS", "connections": 2}],
        }

    def _wireguard(self, now_epoch):
        return [{"name": "Media Node A", "online": True, "latest_handshake": "just now"}]

    def _plex(self):
        return {"active_streams": 1, "transcodes": 0, "servers": [], "sessions": []}

    def _url_checks(self):
        return []

    def _linode_firewall(self):
        return {"enabled": False, "configured": False, "ok": True}

    def _dns_alignment(self, public_ips):
        return []


class CollectorContractTests(unittest.TestCase):
    def test_collect_snapshot_and_history_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig(
                data_dir=root / "data",
                runtime_dir=root / "run",
                primary_interface="eth0",
                sample_interval_seconds=3,
                security_interval_seconds=30,
                maintenance_interval_seconds=900,
                expected_public_hostnames=(),
                geoip=GeoIPConfig(
                    city_database_path=root / "GeoLite2-City.mmdb",
                    asn_database_path=root / "GeoLite2-ASN.mmdb",
                ),
                notifications=NotificationConfig(enabled=False),
                topology_services=(
                    TopologyService(
                        name="Media Node A",
                        eyebrow="MEDIA BACKEND",
                        peer_name="Media Node A",
                        check_names=("Media Node A public",),
                        path="wireguard",
                        link_label="Plex",
                    ),
                ),
            )

            def fake_read_text(path):
                path = str(path)
                values = {
                    "/proc/sys/kernel/random/boot_id": "boot-123\n",
                    "/proc/stat": "cpu  100 0 100 800 0 0 0 0 0 0\n",
                    "/proc/meminfo": "MemTotal: 1000000 kB\nMemAvailable: 750000 kB\n",
                    "/proc/uptime": "3600.00 0.00\n",
                }
                return values[path]

            disk = SimpleNamespace(total=1000, used=250, free=750)
            statvfs = SimpleNamespace(f_files=1000, f_ffree=900)
            counters = NetworkCounters(
                rx_bytes=1_000_000,
                rx_errors=0,
                rx_drops=0,
                tx_bytes=500_000,
                tx_errors=0,
                tx_drops=0,
            )

            with (
                patch("edgewatch.collector._read_text", side_effect=fake_read_text),
                patch("edgewatch.collector._network_counters", return_value=counters),
                patch("edgewatch.collector.shutil.disk_usage", return_value=disk),
                patch("edgewatch.collector.os.statvfs", return_value=statvfs),
                patch("edgewatch.collector.os.getloadavg", return_value=(0.1, 0.2, 0.3)),
                patch("edgewatch.collector.platform.node", return_value="linoleum"),
                patch("edgewatch.collector.platform.release", return_value="6.8.0"),
                patch("edgewatch.collector.platform.platform", return_value="Ubuntu-24.04"),
            ):
                collector = ContractCollector(config, geoip_resolver=FakeGeoIP())
                snapshot, sample = collector.collect()

            self.assertEqual(snapshot["version"], "0.5.4")
            self.assertEqual(snapshot["system"]["hostname"], "linoleum")
            self.assertEqual(snapshot["network"]["interface"], "eth0")
            self.assertEqual(snapshot["network"]["connections"]["established"], 2)
            self.assertEqual(snapshot["plex"]["active_streams"], 1)
            self.assertIn("coverage", snapshot["posture"])
            self.assertEqual(snapshot["topology"]["services"][0]["name"], "Media Node A")
            self.assertEqual(snapshot["topology"]["services"][0]["path"], "wireguard")
            self.assertEqual(sample["interface"], "eth0")
            self.assertEqual(sample["plex_streams"], 1)
            self.assertEqual(sample["public_peers"], 1)
            self.assertIsInstance(sample["risk_score"], int)


if __name__ == "__main__":
    unittest.main()

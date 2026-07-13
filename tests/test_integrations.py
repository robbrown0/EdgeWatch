from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edgewatch.config import GeoIPConfig, LinodeConfig, NotificationConfig, load_secrets
from edgewatch.geoip import GeoIPResolver
from edgewatch.linode import fetch_linode_firewall
from edgewatch.notifications import NotificationManager
from edgewatch.storage import Storage
from edgewatch.web import create_app


class IntegrationUnitTests(unittest.TestCase):
    def test_common_plex_token_and_override(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secrets.toml"
            path.write_text('''
[plex]
token = "common"
[[plex_tokens]]
name = "Media Node A"
token = "specific"
''')
            secrets = load_secrets(path)
            self.assertEqual(secrets.plex_token_for("Media Node A"), "specific")
            self.assertEqual(secrets.plex_token_for("Media Node B"), "common")

    def test_missing_geoip_is_nonfatal(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            resolver = GeoIPResolver(GeoIPConfig(base / "city.mmdb", base / "asn.mmdb", 28))
            self.assertFalse(resolver.status()["city_available"])
            self.assertFalse(resolver.lookup("198.51.100.1")["located"])
            resolver.close()

    def test_notification_new_alert_and_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            storage = Storage(Path(folder) / "edgewatch.db")
            storage.initialize()
            manager = NotificationManager(
                NotificationConfig(enabled=True, minimum_severity="high", recovery_notifications=True),
                type("Secret", (), {"url": "https://example.invalid/topic", "token": ""})(),
                storage,
            )
            insight = [{
                "fingerprint": "test-finding",
                "severity": "high",
                "title": "Test finding",
                "detail": "Detected",
                "remediation": "Review",
            }]
            with patch.object(manager, "_send", return_value=(True, "HTTP 200")) as sender:
                first = manager.process(insight, now_epoch=1000)
                second = manager.process(insight, now_epoch=1001)
                recovery = manager.process([], now_epoch=1002)
            self.assertEqual(len(first), 1)
            self.assertEqual(second, [])
            self.assertEqual(len(recovery), 1)
            self.assertEqual(sender.call_count, 2)

    def test_notification_mute_suppresses_alert_and_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            storage = Storage(Path(folder) / "edgewatch.db")
            storage.initialize()
            manager = NotificationManager(
                NotificationConfig(enabled=True, minimum_severity="high", recovery_notifications=True),
                type("Secret", (), {"url": "https://example.invalid/topic", "token": ""})(),
                storage,
            )
            insight = [{
                "fingerprint": "test-finding",
                "severity": "high",
                "title": "Test finding",
                "detail": "Detected",
                "remediation": "Review",
            }]
            controls = {"test-finding": {"active": True, "resumed_at": None}}
            with patch.object(manager, "_send", return_value=(True, "HTTP 200")) as sender:
                first = manager.process(insight, now_epoch=1000, controls=controls)
                recovery = manager.process([], now_epoch=1002, controls=controls)
            self.assertEqual(first, [])
            self.assertEqual(recovery, [])
            sender.assert_not_called()

    def test_resuming_alerts_notifies_on_next_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            storage = Storage(Path(folder) / "edgewatch.db")
            storage.initialize()
            manager = NotificationManager(
                NotificationConfig(enabled=True, minimum_severity="high", recovery_notifications=True),
                type("Secret", (), {"url": "https://example.invalid/topic", "token": ""})(),
                storage,
            )
            insight = [{
                "fingerprint": "test-finding",
                "severity": "high",
                "title": "Test finding",
                "detail": "Detected",
                "remediation": "Review",
            }]
            with patch.object(manager, "_send", return_value=(True, "HTTP 200")) as sender:
                manager.process(
                    insight,
                    now_epoch=1000,
                    controls={"test-finding": {"active": True}},
                )
                resumed = manager.process(
                    insight,
                    now_epoch=1100,
                    controls={"test-finding": {"active": False, "resumed_at": 1050}},
                )
            self.assertEqual(len(resumed), 1)
            sender.assert_called_once()

    def test_linode_firewall_must_be_attached(self) -> None:
        config = LinodeConfig(enabled=True, linode_id=123, firewall_id=456)
        responses = [
            (200, {"id": 456, "label": "edge", "status": "enabled"}),
            (200, {"inbound_policy": "DROP", "outbound_policy": "ACCEPT", "inbound": [], "outbound": []}),
            (200, {"data": [{"id": 999, "label": "other"}]}),
        ]
        with patch("edgewatch.linode._get_json", side_effect=responses):
            result = fetch_linode_firewall(config, "token")
        self.assertFalse(result["ok"])
        self.assertFalse(result["attached"])

    def test_linode_firewall_attachment_is_verified(self) -> None:
        config = LinodeConfig(enabled=True, linode_id=123, firewall_id=456)
        responses = [
            (200, {"id": 456, "label": "edge", "status": "enabled"}),
            (200, {"inbound_policy": "DROP", "outbound_policy": "ACCEPT", "inbound": [], "outbound": []}),
            (200, {"data": [{"id": 456, "label": "edge"}]}),
        ]
        with patch("edgewatch.linode._get_json", side_effect=responses):
            result = fetch_linode_firewall(config, "token")
        self.assertTrue(result["ok"])
        self.assertTrue(result["attached"])

    def test_installer_isolates_runtime_secrets(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "scripts" / "install.sh").read_text()
        self.assertIn('chown root:root "$SECRETS_FILE"', script)
        self.assertIn('chmod 0600 "$SECRETS_FILE"', script)
        self.assertIn('runuser -u edgewatch -- test -r "$SECRETS_FILE"', script)
        self.assertIn("scripts/discover-identity.py", script)
        self.assertIn("CONFIG_BACKUP=", script)
        self.assertIn("SITE_BACKUP=", script)
        self.assertIn("Restoring the pre-install configuration", script)
        self.assertIn("Restoring the pre-install private site configuration", script)
        self.assertIn('deploy/site.toml.example', script)
        self.assertIn('deploy/site.toml', script)

    def test_installation_artifacts_preserve_least_privilege(self) -> None:
        root = Path(__file__).resolve().parents[1]
        installer = (root / "scripts" / "install.sh").read_text()
        backup = (root / "scripts" / "backup.sh").read_text()
        web_unit = (root / "deploy" / "edgewatch-web.service").read_text()
        monitor_unit = (root / "deploy" / "edgewatch-monitor-users.service").read_text()
        caddy = (root / "deploy" / "Caddyfile.example").read_text()

        self.assertIn('install -d -o edgewatch -g edgewatch -m 0770 "$CONTROL_DIR"', installer)
        self.assertIn('edgewatch-monitor-users.service', installer)
        self.assertIn('MAP_RELATIVE_PATH="edgewatch/static/maps/edgewatch.pmtiles"', installer)
        self.assertIn('ln "$PREVIOUS_TARGET/$MAP_RELATIVE_PATH"', installer)
        self.assertIn('cp --reflink=auto', installer)
        self.assertIn(
            'systemctl restart edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service',
            installer,
        )
        self.assertIn('grep -Fq \"\\\"version\\\":\\\"$VERSION\\\"\"', installer)
        self.assertIn('/var/lib/edgewatch/control/edgewatch-control.db', backup)
        self.assertIn('/etc/edgewatch/site.toml', backup)
        self.assertIn('source.backup(destination)', backup)
        self.assertIn('ReadOnlyPaths=/var/lib/edgewatch', web_unit)
        self.assertIn('ReadWritePaths=/var/lib/edgewatch/control', web_unit)
        self.assertIn('User=edgewatch', monitor_unit)
        self.assertIn('ProtectSystem=strict', monitor_unit)
        for header in (
            'X-Auth-Request-User',
            'X-Auth-Request-Email',
            'X-Auth-Request-Groups',
            'X-Auth-Request-Preferred-Username',
            'X-Forwarded-Email',
            'X-Forwarded-User',
            'Remote-User',
        ):
            self.assertIn(f'request_header -{header}', caddy)
        self.assertIn('copy_headers X-Auth-Request-User', caddy)

    def test_web_routes_allow_only_the_scoped_control_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            config = base / "config.toml"
            config.write_text(f'''
[app]
data_dir = "{base / 'data'}"
runtime_dir = "{base / 'run'}"
[web]
allowed_hosts = ["localhost", "127.0.0.1"]
''')
            app = create_app(str(config))
            api_routes = {
                route.path: set(route.methods or set())
                for route in app.routes
                if route.path.startswith("/api/")
            }
            self.assertIn("/api/v1/live", api_routes)
            self.assertIn("/api/v1/history", api_routes)
            self.assertEqual(
                api_routes["/api/v1/finding-acknowledgements"],
                {"POST"},
            )
            for path, methods in api_routes.items():
                if path == "/api/v1/finding-acknowledgements":
                    continue
                self.assertTrue(methods.issubset({"GET", "HEAD"}), path)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from edgewatch.collector import Collector
from edgewatch.config import AppConfig, PeerAlias


class FakeGeoIP:
    LOCATIONS = {
        "203.0.113.10": {
            "located": True,
            "latitude": 37.751,
            "longitude": -97.822,
            "country": "United States",
            "country_code": "US",
            "region": "Kansas",
            "city": "",
        },
        "198.51.100.20": {
            "located": True,
            "latitude": -33.494,
            "longitude": 143.2104,
            "country": "Australia",
            "country_code": "AU",
            "region": "",
            "city": "",
        },
    }

    def lookup(self, ip: str) -> dict[str, object]:
        return dict(self.LOCATIONS.get(ip, {"located": False}))

    def status(self) -> dict[str, object]:
        return {"city_available": True, "asn_available": True, "files": []}

    def close(self) -> None:
        return None


class ConnectionIntelligenceTests(unittest.TestCase):
    def test_connection_classification_and_recent_window(self) -> None:
        current_ss = {
            "value": "\n".join(
                [
                    '0 0 203.0.113.10:443 198.51.100.20:50123 users:(("caddy",pid=10,fd=5))',
                    '0 0 10.200.0.1:40000 10.200.0.2:32400 users:(("caddy",pid=10,fd=6))',
                    '0 0 127.0.0.1:8765 127.0.0.1:50000 users:(("python",pid=20,fd=7))',
                    '0 0 100.64.0.1:40001 100.64.0.2:443 users:(("caddy",pid=10,fd=8))',
                ]
            )
        }

        def runner(args: list[str], _timeout: float) -> tuple[int, str, str]:
            if args[:2] == ["ss", "-H"]:
                return 0, current_ss["value"], ""
            if args[:3] == ["ip", "-j", "address"]:
                return (
                    0,
                    json.dumps([{"addr_info": [{"local": "203.0.113.10"}]}]),
                    "",
                )
            return 0, "", ""

        config = AppConfig(
            flow_recent_seconds=60,
            peer_aliases=(PeerAlias(name="Media Node A", allowed_ip="10.200.0.2/32"),),
        )
        collector = Collector(config, command_runner=runner, geoip_resolver=FakeGeoIP())
        listeners = [{"protocol": "tcp", "port": 443, "public_bind": True}]

        with patch(
            "edgewatch.collector._is_public_ip",
            side_effect=lambda value: value in {"203.0.113.10", "198.51.100.20"},
        ):
            first = collector._connections(listeners, 1_000)
        self.assertEqual(first["established"], 4)
        self.assertEqual(first["public_connection_count"], 1)
        self.assertEqual(first["internal_connection_count"], 2)
        self.assertEqual(first["local_connection_count"], 1)
        self.assertEqual(first["public_peer_count"], 1)
        self.assertEqual(first["unique_public_peer_count"], 1)
        self.assertEqual(first["loopback_connection_count"], 1)
        self.assertEqual(first["recent_public_peer_count"], 1)
        self.assertTrue(first["public_peers"][0]["active"])
        self.assertIn("Media Node A", {peer["name"] for peer in first["internal_peers"]})
        self.assertEqual(first["origin"]["label"], "EdgeWatch VPS")

        current_ss["value"] = "\n".join(
            [
                '0 0 10.200.0.1:40000 10.200.0.2:32400 users:(("caddy",pid=10,fd=6))',
                '0 0 127.0.0.1:8765 127.0.0.1:50000 users:(("python",pid=20,fd=7))',
            ]
        )
        with patch(
            "edgewatch.collector._is_public_ip",
            side_effect=lambda value: value in {"203.0.113.10", "198.51.100.20"},
        ):
            second = collector._connections(listeners, 1_030)
        self.assertEqual(second["public_peer_count"], 0)
        self.assertEqual(second["recent_public_peer_count"], 1)
        self.assertFalse(second["recent_public_peers"][0]["active"])
        self.assertEqual(second["recent_public_peers"][0]["seconds_since_seen"], 30)

        with patch(
            "edgewatch.collector._is_public_ip",
            side_effect=lambda value: value in {"203.0.113.10", "198.51.100.20"},
        ):
            third = collector._connections(listeners, 1_061)
        self.assertEqual(third["recent_public_peer_count"], 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import edgewatch.monitor_users as monitor_users


class MonitorUsersTests(unittest.TestCase):
    def setUp(self) -> None:
        with monitor_users._lock:
            monitor_users._sessions.clear()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            monitor_users.MonitorUsersHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            headers=headers or {},
            data=data,
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return int(response.status), json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return int(exc.code), json.loads(exc.read())


    def test_roster_is_bounded_and_identity_fields_are_limited(self) -> None:
        status, payload = self.request(
            "/api/v1/monitor-users/heartbeat",
            method="POST",
            headers={
                "X-Auth-Request-Email": ("a" * 300) + "@example.com",
                "X-Auth-Request-User": "Display " + ("N" * 200),
                "User-Agent": "Agent/" + ("x" * 900),
                "X-Forwarded-For": "203.0.113.10",
            },
            data=b"",
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        with monitor_users._lock:
            user = next(iter(monitor_users._sessions.values()))
        self.assertLessEqual(len(str(user["email"])), 254)
        self.assertLessEqual(len(str(user["display_name"])), 80)

        now = time.time()
        with monitor_users._lock:
            for index in range(monitor_users.MAX_ACTIVE_SESSIONS + 25):
                monitor_users._sessions[f"synthetic-{index}"] = {
                    "session_id": f"synthetic-{index}",
                    "display_name": "Synthetic",
                    "email": f"synthetic-{index}@example.com",
                    "device": "Test",
                    "browser": "Test",
                    "first_seen_epoch": now + index,
                    "last_seen_epoch": now + index,
                }

        status, _ = self.request(
            "/api/v1/monitor-users/heartbeat",
            method="POST",
            headers={
                "X-Auth-Request-Email": "bounded@example.com",
                "User-Agent": "Bounded/1.0",
            },
            data=b"",
        )
        self.assertEqual(status, 200)
        with monitor_users._lock:
            self.assertLessEqual(
                len(monitor_users._sessions),
                monitor_users.MAX_ACTIVE_SESSIONS,
            )

    def test_health_and_authenticated_heartbeat_roster(self) -> None:
        status, payload = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

        status, payload = self.request(
            "/api/v1/monitor-users/heartbeat",
            method="POST",
            data=b"",
        )
        self.assertEqual(status, 401)
        self.assertIn("identity", str(payload["error"]))

        status, payload = self.request(
            "/api/v1/monitor-users/heartbeat",
            method="POST",
            headers={
                "X-Auth-Request-Email": "alex@example.com",
                "X-Auth-Request-User": "Alex Example",
                "User-Agent": (
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
                    "AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
                ),
            },
            data=b"",
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

        status, payload = self.request("/api/v1/monitor-users")
        self.assertEqual(status, 200)
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["user_count"], 1)
        user = payload["users"][0]
        self.assertEqual(user["email"], "alex@example.com")
        self.assertEqual(user["display_name"], "Alex Example")
        self.assertEqual(user["device"], "iPhone")
        self.assertEqual(user["browser"], "Safari")
        self.assertNotIn("address", user)

    def test_display_name_and_browser_classification(self) -> None:
        self.assertEqual(monitor_users.display_name("jane_doe@example.com"), "Jane Doe")
        self.assertEqual(
            monitor_users.device_and_browser("Mozilla/5.0 (Windows NT 10.0) Edg/131.0"),
            ("Windows", "Microsoft Edge"),
        )


if __name__ == "__main__":
    unittest.main()

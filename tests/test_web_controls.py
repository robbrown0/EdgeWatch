from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from edgewatch.storage import atomic_write_json
from edgewatch.web import create_app


async def asgi_request(app, method: str, path: str, *, headers: dict[str, str] | None = None, body: bytes = b""):
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    messages: list[dict[str, object]] = []
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("localhost", 80),
        "state": {},
    }
    await app(scope, receive, send)
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    response_headers = {
        key.decode().lower(): value.decode()
        for message in messages if message["type"] == "http.response.start"
        for key, value in message.get("headers", [])
    }
    response_body = b"".join(
        message.get("body", b"")
        for message in messages if message["type"] == "http.response.body"
    )
    return status, response_headers, response_body


class WebControlTests(unittest.TestCase):
    def make_app(self, base: Path):
        config = base / "config.toml"
        config.write_text(f'''
[app]
data_dir = "{base / 'data'}"
runtime_dir = "{base / 'run'}"
[web]
allowed_hosts = ["localhost", "127.0.0.1"]
[identity]
provider = "Microsoft Entra ID"
directory_name = "Example Directory"
tenant_id = "11111111-2222-3333-4444-555555555555"
application_name = "EdgeWatch Production"
client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
access_label = "Assigned enterprise application user"
session_lifetime = "8 hours"
session_refresh = "Every 1 hour"
''')
        (base / "run").mkdir(parents=True, exist_ok=True)
        atomic_write_json(
            base / "run" / "latest.json",
            {
                "posture": {
                    "insights": [{
                        "fingerprint": "ssh-password-authentication",
                        "title": "SSH password authentication is enabled",
                        "category": "SSH",
                        "severity": "medium",
                        "score": 12,
                    }]
                }
            },
        )
        return create_app(str(config))

    def request(self, app, method, path, *, headers=None, body=b""):
        return asyncio.run(asgi_request(app, method, path, headers=headers, body=body))

    def valid_headers(self):
        return {
            "host": "localhost",
            "origin": "http://localhost",
            "content-type": "application/json",
            "x-edgewatch-action": "finding-acknowledgement",
            "x-auth-request-email": "alex@example.com",
        }

    def test_identity_metadata_requires_authentication_and_omits_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = self.make_app(Path(folder))

            status, _, _ = self.request(
                app,
                "GET",
                "/api/v1/identity",
                headers={"host": "localhost"},
            )
            self.assertEqual(status, 401)

            status, headers, body = self.request(
                app,
                "GET",
                "/api/v1/identity",
                headers={
                    "host": "localhost",
                    "x-auth-request-email": "alex@example.com",
                },
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(headers["cache-control"], "no-store")
            payload = json.loads(body)
            self.assertEqual(payload["directory_name"], "Example Directory")
            self.assertEqual(
                payload["tenant_id"],
                "11111111-2222-3333-4444-555555555555",
            )
            self.assertEqual(
                payload["client_id"],
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            )
            self.assertEqual(payload["session_lifetime"], "8 hours")
            self.assertTrue(payload["configured"])
            self.assertNotIn("client_secret", payload)
            self.assertNotIn("cookie_secret", payload)
            self.assertNotIn("token", payload)

    def test_acknowledge_and_resume(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = self.make_app(Path(folder))
            request_body = json.dumps({
                "fingerprint": "ssh-password-authentication",
                "acknowledged": True,
            }).encode()
            status, headers, body = self.request(
                app,
                "POST",
                "/api/v1/finding-acknowledgements",
                headers=self.valid_headers(),
                body=request_body,
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(headers["cache-control"], "no-store")
            payload = json.loads(body)
            self.assertTrue(payload["changed"])
            self.assertTrue(payload["acknowledgement"]["active"])

            resume_body = json.dumps({
                "fingerprint": "ssh-password-authentication",
                "acknowledged": False,
            }).encode()
            status, _, body = self.request(
                app,
                "POST",
                "/api/v1/finding-acknowledgements",
                headers=self.valid_headers(),
                body=resume_body,
            )
            self.assertEqual(status, 200, body)
            self.assertFalse(json.loads(body)["acknowledgement"]["active"])

    def test_csrf_identity_and_active_finding_guards(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = self.make_app(Path(folder))
            body = json.dumps({
                "fingerprint": "ssh-password-authentication",
                "acknowledged": True,
            }).encode()

            headers = self.valid_headers()
            headers.pop("x-edgewatch-action")
            status, _, _ = self.request(app, "POST", "/api/v1/finding-acknowledgements", headers=headers, body=body)
            self.assertEqual(status, 403)

            headers = self.valid_headers()
            headers["origin"] = "https://evil.example"
            status, _, _ = self.request(app, "POST", "/api/v1/finding-acknowledgements", headers=headers, body=body)
            self.assertEqual(status, 403)

            headers = self.valid_headers()
            headers.pop("x-auth-request-email")
            status, _, _ = self.request(app, "POST", "/api/v1/finding-acknowledgements", headers=headers, body=body)
            self.assertEqual(status, 401)

            headers = self.valid_headers()
            headers.pop("x-auth-request-email")
            headers["x-forwarded-email"] = "spoofed@example.com"
            status, _, _ = self.request(app, "POST", "/api/v1/finding-acknowledgements", headers=headers, body=body)
            self.assertEqual(status, 401)

            missing = json.dumps({"fingerprint": "not-active", "acknowledged": True}).encode()
            status, _, _ = self.request(app, "POST", "/api/v1/finding-acknowledgements", headers=self.valid_headers(), body=missing)
            self.assertEqual(status, 404)

    def test_other_mutations_remain_blocked_and_body_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = self.make_app(Path(folder))
            status, _, _ = self.request(app, "POST", "/api/v1/history", headers={"host": "localhost"})
            self.assertEqual(status, 405)

            headers = self.valid_headers()
            headers["content-length"] = "5000"
            status, _, _ = self.request(
                app,
                "POST",
                "/api/v1/finding-acknowledgements",
                headers=headers,
                body=b"{}",
            )
            self.assertEqual(status, 413)


if __name__ == "__main__":
    unittest.main()

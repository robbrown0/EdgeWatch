#!/usr/bin/env python3

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from hashlib import sha256
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from typing import Any
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8766
ACTIVE_WINDOW_SECONDS = 300
MAX_ACTIVE_SESSIONS = 500

_sessions: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


def clean(value: object) -> str:
    return str(value or "").strip()


def bounded(value: object, limit: int) -> str:
    return clean(value)[: max(0, int(limit))]


def display_name(value: str) -> str:
    candidate = clean(value)

    if "@" in candidate:
        candidate = candidate.split("@", 1)[0]

    candidate = (
        candidate
        .replace(".", " ")
        .replace("_", " ")
        .replace("-", " ")
    )

    words = [
        word
        for word in candidate.split()
        if word
    ]

    if not words:
        return "Signed-in user"

    return " ".join(
        word[:1].upper() + word[1:]
        for word in words
    )


def device_and_browser(
    user_agent: str,
) -> tuple[str, str]:
    agent = clean(user_agent)
    lowered = agent.lower()

    if "ipad" in lowered:
        device = "iPad"
    elif "iphone" in lowered:
        device = "iPhone"
    elif "android" in lowered:
        device = "Android"
    elif "windows" in lowered:
        device = "Windows"
    elif "macintosh" in lowered:
        device = "Mac"
    elif "linux" in lowered:
        device = "Linux"
    else:
        device = "Unknown device"

    if "edg/" in lowered:
        browser = "Microsoft Edge"
    elif "firefox/" in lowered:
        browser = "Firefox"
    elif (
        "chrome/" in lowered
        and "chromium" not in lowered
    ):
        browser = "Chrome"
    elif (
        "safari/" in lowered
        and "chrome/" not in lowered
    ):
        browser = "Safari"
    else:
        browser = "Web browser"

    return device, browser


class MonitorUsersHandler(
    BaseHTTPRequestHandler
):
    server_version = "EdgeWatchMonitorUsers/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        return

    def send_json(
        self,
        status: int,
        payload: object,
    ) -> None:
        body = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Cache-Control",
            "no-store",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(body)

    def authenticated_identity(
        self,
    ) -> tuple[str, str] | None:
        preferred = clean(
            self.headers.get(
                "X-Auth-Request-Preferred-Username"
            )
        )

        email = clean(
            self.headers.get(
                "X-Auth-Request-Email"
            )
        )

        user = clean(
            self.headers.get(
                "X-Auth-Request-User"
            )
        )

        identity = (
            email
            or preferred
            or user
        )

        if not identity:
            return None

        name_source = (
            user
            if user and "@" not in user
            else identity
        )

        return (
            bounded(identity.lower(), 254),
            bounded(display_name(name_source), 80),
        )

    def public_address(self) -> str:
        forwarded = clean(
            self.headers.get(
                "X-Forwarded-For"
            )
        )

        if forwarded:
            return forwarded.split(
                ",",
                1,
            )[0].strip()

        return clean(
            self.client_address[0]
        )

    def register_heartbeat(self) -> bool:
        identity = (
            self.authenticated_identity()
        )

        if identity is None:
            return False

        email, name = identity
        now = time.time()

        user_agent = bounded(
            self.headers.get(
                "User-Agent"
            ),
            512,
        )

        address = bounded(
            self.public_address(),
            64,
        )

        device, browser = (
            device_and_browser(
                user_agent
            )
        )

        session_key = sha256(
            (
                email
                + "\n"
                + address
                + "\n"
                + user_agent
            ).encode("utf-8")
        ).hexdigest()[:16]

        with _lock:
            previous = _sessions.get(
                session_key
            )

            first_seen = (
                float(
                    previous.get(
                        "first_seen_epoch",
                        now,
                    )
                )
                if previous
                else now
            )

            _sessions[session_key] = {
                "session_id": session_key,
                "display_name": name,
                "email": email,
                "device": device,
                "browser": browser,
                "first_seen_epoch": first_seen,
                "last_seen_epoch": now,
            }

            if len(_sessions) > MAX_ACTIVE_SESSIONS:
                oldest = sorted(
                    _sessions,
                    key=lambda key: float(
                        _sessions[key].get("last_seen_epoch", 0)
                    ),
                )
                for stale_key in oldest[: len(_sessions) - MAX_ACTIVE_SESSIONS]:
                    _sessions.pop(stale_key, None)

        return True

    def current_roster(self) -> dict[str, Any]:
        now = time.time()
        active: list[dict[str, Any]] = []

        with _lock:
            expired = [
                session_id
                for session_id, value
                in _sessions.items()
                if (
                    now
                    - float(
                        value.get(
                            "last_seen_epoch",
                            0,
                        )
                    )
                    > ACTIVE_WINDOW_SECONDS
                )
            ]

            for session_id in expired:
                _sessions.pop(
                    session_id,
                    None,
                )

            for value in _sessions.values():
                last_seen = float(
                    value[
                        "last_seen_epoch"
                    ]
                )

                first_seen = float(
                    value[
                        "first_seen_epoch"
                    ]
                )

                active.append({
                    "session_id":
                        value["session_id"],

                    "display_name":
                        value["display_name"],

                    "email":
                        value["email"],

                    "device":
                        value["device"],

                    "browser":
                        value["browser"],

                    "first_seen":
                        utc_iso(first_seen),

                    "last_seen":
                        utc_iso(last_seen),

                    "last_seen_seconds_ago":
                        max(
                            0,
                            int(
                                now
                                - last_seen
                            ),
                        ),
                })

        active.sort(
            key=lambda item:
                item[
                    "last_seen_seconds_ago"
                ]
        )

        unique_users = {
            item["email"]
            for item in active
        }

        return {
            "active_count": len(active),
            "user_count": len(
                unique_users
            ),
            "window_seconds":
                ACTIVE_WINDOW_SECONDS,
            "generated_at": utc_iso(now),
            "users": active,
        }

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlsplit(
            self.path
        ).path

        if path == "/healthz":
            self.send_json(
                200,
                {"ok": True},
            )
            return

        if (
            path
            == "/api/v1/monitor-users"
        ):
            self.send_json(
                200,
                self.current_roster(),
            )
            return

        self.send_json(
            404,
            {"error": "not found"},
        )

    def do_POST(self) -> None:
        path = urlsplit(
            self.path
        ).path

        if (
            path
            !=
            "/api/v1/monitor-users/heartbeat"
        ):
            self.send_json(
                404,
                {"error": "not found"},
            )
            return

        if not self.register_heartbeat():
            self.send_json(
                401,
                {
                    "error":
                        "authenticated identity missing"
                },
            )
            return

        self.send_json(
            200,
            {"ok": True},
        )


def main() -> None:
    server = ThreadingHTTPServer(
        (HOST, PORT),
        MonitorUsersHandler,
    )

    server.serve_forever(
        poll_interval=0.5
    )


if __name__ == "__main__":
    main()

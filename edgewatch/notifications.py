from __future__ import annotations

import time
import urllib.error
import urllib.request

from .config import NotificationConfig, NtfySecret
from .storage import Storage

SEVERITY_RANK = {"ok": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
PRIORITY = {"low": "low", "medium": "default", "high": "high", "critical": "urgent"}
TAGS = {
    "low": "information_source",
    "medium": "warning",
    "high": "warning,shield",
    "critical": "rotating_light,skull",
}


class NotificationManager:
    def __init__(self, config: NotificationConfig, secret: NtfySecret, storage: Storage):
        self.config = config
        self.secret = secret
        self.storage = storage

    @property
    def configured(self) -> bool:
        return self.config.enabled and self.config.provider == "ntfy" and bool(self.secret.url)

    def _send(self, title: str, message: str, severity: str, fingerprint: str) -> tuple[bool, str]:
        headers = {
            "Title": title[:120],
            "Priority": PRIORITY.get(severity, "default"),
            "Tags": TAGS.get(severity, "shield"),
            "User-Agent": "EdgeWatch/0.5.5",
            "Content-Type": "text/plain; charset=utf-8",
        }
        if self.config.dashboard_url:
            headers["Click"] = self.config.dashboard_url
        if self.secret.token:
            headers["Authorization"] = f"Bearer {self.secret.token}"
        request = urllib.request.Request(
            self.secret.url,
            data=message.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            # Notification configuration accepts only HTTP or HTTPS URLs.
            with urllib.request.urlopen(request, timeout=8.0) as response:  # nosec B310
                response.read(65536)
                ok = 200 <= int(response.status) < 300
                return ok, f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            return False, f"HTTP {exc.code} {exc.reason}"
        except Exception as exc:
            return False, str(exc)[:240]

    def test(self) -> tuple[bool, str]:
        if not self.configured:
            return False, "Notifications are disabled or ntfy.url is missing"
        return self._send(
            "EdgeWatch notification test",
            "EdgeWatch 0.5.5 can deliver push notifications from this VPS.",
            "medium",
            "notification-test",
        )

    def process(
        self,
        insights: list[dict[str, object]],
        now_epoch: int | None = None,
        controls: dict[str, dict[str, object]] | None = None,
    ) -> list[dict[str, object]]:
        if not self.configured:
            return []

        now = now_epoch or int(time.time())
        control_state = controls or {}
        minimum = SEVERITY_RANK.get(
            self.config.minimum_severity,
            SEVERITY_RANK["high"],
        )
        active = {
            str(item.get("fingerprint")): item
            for item in insights
            if SEVERITY_RANK.get(str(item.get("severity")), 0) >= minimum
            and item.get("fingerprint")
        }
        states = self.storage.alert_states()
        results: list[dict[str, object]] = []

        for fingerprint, item in active.items():
            severity = str(item.get("severity") or "medium")
            title = str(item.get("title") or "EdgeWatch finding")
            detail = str(item.get("detail") or "")
            remediation = str(item.get("remediation") or "")
            state = states.get(fingerprint)
            control = control_state.get(fingerprint) or {}
            muted = bool(control.get("active"))
            previous_rank = (
                SEVERITY_RANK.get(str(state.get("severity")), 0)
                if state
                else 0
            )
            last_notified = int(state.get("last_notified_ts", 0)) if state else 0
            resumed_at = int(control.get("resumed_at") or 0)
            is_new = not state or not bool(state.get("active"))
            escalated = SEVERITY_RANK.get(severity, 0) > previous_rank
            resumed = resumed_at > last_notified
            cooldown_elapsed = now - last_notified >= self.config.cooldown_seconds
            notify = not muted and (is_new or escalated or resumed or cooldown_elapsed)
            notified_at = last_notified

            if notify:
                message = detail
                if remediation:
                    message += f"\n\nRecommended: {remediation}"
                ok, result_detail = self._send(
                    f"EdgeWatch: {title}",
                    message,
                    severity,
                    fingerprint,
                )
                self.storage.add_notification_log(
                    now,
                    "ntfy",
                    fingerprint,
                    ok,
                    result_detail,
                )
                results.append(
                    {
                        "fingerprint": fingerprint,
                        "success": ok,
                        "detail": result_detail,
                    }
                )
                if ok:
                    notified_at = now

            self.storage.upsert_alert_state(
                fingerprint,
                True,
                severity,
                title,
                now,
                notified_at,
            )

        for fingerprint, state in states.items():
            if not bool(state.get("active")) or fingerprint in active:
                continue

            control = control_state.get(fingerprint) or {}
            muted = bool(control.get("active"))
            notified_at = int(state.get("last_notified_ts", 0))
            title = str(state.get("title") or "Finding")

            if self.config.recovery_notifications and not muted:
                ok, result_detail = self._send(
                    f"EdgeWatch recovered: {title}",
                    "The condition is no longer present in the current EdgeWatch assessment.",
                    "low",
                    fingerprint,
                )
                self.storage.add_notification_log(
                    now,
                    "ntfy",
                    fingerprint,
                    ok,
                    result_detail,
                )
                results.append(
                    {
                        "fingerprint": fingerprint,
                        "success": ok,
                        "detail": result_detail,
                        "recovery": True,
                    }
                )
                if ok:
                    notified_at = now

            self.storage.upsert_alert_state(
                fingerprint,
                False,
                str(state.get("severity") or "medium"),
                title,
                int(state.get("last_seen_ts") or now),
                notified_at,
            )

        return results

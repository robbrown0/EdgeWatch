from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from .config import LinodeConfig

API_BASE = "https://api.linode.com/v4"


def _get_json(
    path: str,
    token: str,
    timeout: float = 6.0,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "EdgeWatch/0.5.5",
            "Connection": "close",
        },
        method="GET",
    )

    # API_BASE is a fixed HTTPS endpoint.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        payload = json.loads(
            response.read(2_000_000).decode(
                "utf-8",
                errors="replace",
            )
        )
        return (
            int(response.status),
            payload if isinstance(payload, dict) else {},
        )


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(
            exc.read(65536).decode(
                "utf-8",
                errors="replace",
            )
        )
    except Exception:
        return str(exc.reason)

    errors = payload.get("errors") if isinstance(payload, dict) else None

    if not isinstance(errors, list):
        return str(exc.reason)

    reasons = [
        str(item.get("reason"))
        for item in errors
        if isinstance(item, dict) and item.get("reason")
    ]

    return "; ".join(reasons) or str(exc.reason)



def fetch_linode_transfer(
    token: str,
) -> dict[str, object]:
    """Fetch the account's current monthly network transfer usage."""

    if not token:
        return {
            "ok": False,
            "configured": False,
            "status": "API token missing",
        }

    started = time.monotonic()

    try:
        _status, payload = _get_json(
            "/account/transfer",
            token,
        )

        used_gb = float(payload.get("used") or 0.0)
        quota_gb = float(payload.get("quota") or 0.0)
        billable_gb = float(payload.get("billable") or 0.0)

        if used_gb < 0:
            raise ValueError("Linode transfer usage was negative")

        if quota_gb <= 0:
            raise ValueError("Linode transfer quota was missing or invalid")

        return {
            "ok": True,
            "configured": True,
            "status": "available",
            "used_gb": used_gb,
            "quota_gb": quota_gb,
            "billable_gb": billable_gb,
            "source": "linode_account_api",
            "latency_ms": round(
                (time.monotonic() - started) * 1000
            ),
        }

    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "configured": True,
            "status": int(exc.code),
            "detail": _http_error_detail(exc)[:180],
            "latency_ms": round(
                (time.monotonic() - started) * 1000
            ),
        }

    except Exception as exc:
        return {
            "ok": False,
            "configured": True,
            "status": "failed",
            "detail": str(exc)[:180],
            "latency_ms": None,
        }


def _legacy_firewall_attached(
    config: LinodeConfig,
    token: str,
) -> tuple[bool, str, int | None]:
    try:
        _status, payload = _get_json(
            f"/linode/instances/{config.linode_id}/firewalls",
            token,
        )
    except urllib.error.HTTPError as exc:
        detail = _http_error_detail(exc)

        if (
            exc.code == 400
            and "Linode Interfaces" in detail
        ):
            return _interface_firewall_attached(config, token)

        raise

    rows = payload.get("data")

    if not isinstance(rows, list):
        rows = []

    attached = any(
        isinstance(item, dict)
        and int(item.get("id") or 0) == config.firewall_id
        for item in rows
    )

    return attached, "linode", None


def _interface_firewall_attached(
    config: LinodeConfig,
    token: str,
) -> tuple[bool, str, int | None]:
    _status, payload = _get_json(
        f"/linode/instances/{config.linode_id}/interfaces",
        token,
    )

    interfaces = payload.get("interfaces")

    if not isinstance(interfaces, list):
        interfaces = payload.get("data")

    if not isinstance(interfaces, list):
        interfaces = []

    matching_interface_id: int | None = None

    # Prefer default-route interfaces first.  Public Linode interfaces
    # normally have the default IPv4 and IPv6 routes.
    ordered_interfaces = sorted(
        (
            item
            for item in interfaces
            if isinstance(item, dict)
        ),
        key=lambda item: not bool(
            isinstance(item.get("default_route"), dict)
            and (
                item["default_route"].get("ipv4")
                or item["default_route"].get("ipv6")
            )
        ),
    )

    for interface in ordered_interfaces:
        interface_id = int(interface.get("id") or 0)

        if interface_id <= 0:
            continue

        _fw_status, firewall_payload = _get_json(
            (
                f"/linode/instances/{config.linode_id}"
                f"/interfaces/{interface_id}/firewalls"
            ),
            token,
        )

        firewalls = firewall_payload.get("data")

        if not isinstance(firewalls, list):
            firewalls = []

        attached = any(
            isinstance(item, dict)
            and int(item.get("id") or 0) == config.firewall_id
            for item in firewalls
        )

        if attached:
            matching_interface_id = interface_id
            return True, "linode_interface", matching_interface_id

    return False, "linode_interface", matching_interface_id


def fetch_linode_firewall(
    config: LinodeConfig,
    token: str,
) -> dict[str, object]:
    if not config.enabled:
        return {
            "enabled": False,
            "configured": False,
            "ok": True,
            "status": "disabled",
        }

    if config.linode_id <= 0 or config.firewall_id <= 0:
        missing = (
            "linode_id"
            if config.linode_id <= 0
            else "firewall_id"
        )

        return {
            "enabled": True,
            "configured": False,
            "ok": False,
            "status": f"{missing} missing",
        }

    if not token:
        return {
            "enabled": True,
            "configured": False,
            "ok": False,
            "status": "API token missing",
        }

    started = time.monotonic()

    try:
        _status, firewall = _get_json(
            f"/networking/firewalls/{config.firewall_id}",
            token,
        )

        _rules_status, rules = _get_json(
            f"/networking/firewalls/{config.firewall_id}/rules",
            token,
        )

        attached, attachment_type, interface_id = (
            _legacy_firewall_attached(config, token)
        )

        inbound = (
            rules.get("inbound")
            if isinstance(rules.get("inbound"), list)
            else []
        )

        outbound = (
            rules.get("outbound")
            if isinstance(rules.get("outbound"), list)
            else []
        )

        inbound_policy = str(
            rules.get("inbound_policy") or ""
        ).upper()

        outbound_policy = str(
            rules.get("outbound_policy") or ""
        ).upper()

        status = str(
            firewall.get("status") or "unknown"
        ).lower()

        ok = (
            status == "enabled"
            and attached
            and (
                not config.require_inbound_drop
                or inbound_policy == "DROP"
            )
        )

        inbound_rows: list[dict[str, object]] = []

        for rule in inbound[:25]:
            if not isinstance(rule, dict):
                continue

            inbound_rows.append(
                {
                    "label": str(
                        rule.get("label") or "Unnamed rule"
                    ),
                    "action": str(
                        rule.get("action") or ""
                    ).upper(),
                    "protocol": str(
                        rule.get("protocol") or ""
                    ).upper(),
                    "ports": str(
                        rule.get("ports") or "all"
                    ),
                    "addresses": rule.get("addresses") or {},
                }
            )

        return {
            "enabled": True,
            "configured": True,
            "ok": ok,
            "id": config.firewall_id,
            "linode_id": config.linode_id,
            "label": str(
                firewall.get("label")
                or f"Firewall {config.firewall_id}"
            ),
            "status": status,
            "attached": attached,
            "attachment_type": attachment_type,
            "interface_id": interface_id,
            "inbound_policy": inbound_policy,
            "outbound_policy": outbound_policy,
            "inbound_rules": inbound_rows,
            "inbound_rule_count": len(inbound),
            "outbound_rule_count": len(outbound),
            "latency_ms": round(
                (time.monotonic() - started) * 1000
            ),
        }

    except urllib.error.HTTPError as exc:
        detail = _http_error_detail(exc)

        return {
            "enabled": True,
            "configured": True,
            "ok": False,
            "status": int(exc.code),
            "detail": detail[:180],
            "latency_ms": round(
                (time.monotonic() - started) * 1000
            ),
        }

    except Exception as exc:
        return {
            "enabled": True,
            "configured": True,
            "ok": False,
            "status": "failed",
            "detail": str(exc)[:180],
            "latency_ms": None,
        }

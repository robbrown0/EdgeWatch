from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ConnectionProfile:
    account_name: str
    account_id: str
    person_name: str
    device_name: str
    client_identifier: str
    service: str
    confidence: str
    evidence: tuple[str, ...]


def correlate_plex_activity(
    activity: dict[str, Any],
    sessions: list[dict[str, Any]],
) -> ConnectionProfile:
    client_identifier = str(activity.get("client_identifier") or "").strip()

    if not client_identifier:
        return ConnectionProfile(
            account_name="",
            account_id="",
            person_name="",
            device_name=str(activity.get("device_name") or activity.get("device") or ""),
            client_identifier="",
            service="plex",
            confidence="unknown",
            evidence=("No stable Plex client identifier was observed.",),
        )

    matches = [
        session
        for session in sessions
        if str(session.get("client_identifier") or "").strip() == client_identifier
    ]

    if len(matches) != 1:
        reason = (
            "No active Plex session matched the client identifier."
            if not matches
            else "Multiple active Plex sessions matched the client identifier."
        )
        return ConnectionProfile(
            account_name="",
            account_id="",
            person_name="",
            device_name=str(activity.get("device_name") or activity.get("device") or ""),
            client_identifier=client_identifier,
            service="plex",
            confidence="unknown",
            evidence=(reason,),
        )

    session = matches[0]

    return ConnectionProfile(
        account_name=str(session.get("user") or ""),
        account_id=str(session.get("user_id") or ""),
        person_name="",
        device_name=str(
            session.get("player")
            or activity.get("device_name")
            or activity.get("device")
            or ""
        ),
        client_identifier=client_identifier,
        service="plex",
        confidence="confirmed",
        evidence=(
            "Caddy X-Plex-Client-Identifier matched Plex Player.machineIdentifier.",
            "Plex supplied the authenticated account for the active session.",
        ),
    )

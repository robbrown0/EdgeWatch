from __future__ import annotations

from dataclasses import asdict, dataclass
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

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["evidence"] = list(self.evidence)
        return value


def _text(value: object) -> str:
    return str(value or "").strip()


def correlate_plex_activity(
    activity: dict[str, Any],
    sessions: list[dict[str, Any]],
) -> ConnectionProfile:
    """Correlate sanitized Caddy activity with one active Plex session.

    A confirmed result requires an exact stable client identifier match and a
    single matching active session. Usernames, IP addresses, and device labels
    alone are intentionally insufficient.
    """

    client_identifier = _text(activity.get("client_identifier"))
    fallback_device = _text(activity.get("device_name") or activity.get("device"))

    if not client_identifier:
        return ConnectionProfile(
            account_name="",
            account_id="",
            person_name="",
            device_name=fallback_device,
            client_identifier="",
            service="plex",
            confidence="unknown",
            evidence=("No stable Plex client identifier was observed.",),
        )

    matches = [
        session
        for session in sessions
        if _text(session.get("client_identifier")) == client_identifier
        and _text(session.get("state")).lower() != "stopped"
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
            device_name=fallback_device,
            client_identifier=client_identifier,
            service="plex",
            confidence="unknown",
            evidence=(reason,),
        )

    session = matches[0]
    return ConnectionProfile(
        account_name=_text(session.get("user")),
        account_id=_text(session.get("user_id")),
        person_name="",
        device_name=_text(session.get("player")) or fallback_device,
        client_identifier=client_identifier,
        service="plex",
        confidence="confirmed",
        evidence=(
            "Caddy X-Plex-Client-Identifier matched Plex Player.machineIdentifier.",
            "Plex supplied the authenticated account for the active session.",
        ),
    )


def annotate_connection_profiles(
    connections: dict[str, Any],
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attach conservative identity profiles to Plex-related public peers."""

    confirmed = 0
    unknown = 0

    for collection_name in ("public_peers", "recent_public_peers"):
        rows = connections.get(collection_name)
        if not isinstance(rows, list):
            continue

        for row in rows:
            if not isinstance(row, dict):
                continue
            activity = row.get("activity")
            if not isinstance(activity, dict):
                continue

            kind = _text(activity.get("kind")).lower()
            if not kind.startswith("plex"):
                continue

            profile = correlate_plex_activity(activity, sessions)
            row["connection_profile"] = profile.to_dict()
            if profile.confidence == "confirmed":
                confirmed += 1
                if profile.device_name and not row.get("display_name"):
                    row["display_name"] = profile.device_name
            else:
                unknown += 1

    connections["identity_summary"] = {
        "confirmed": confirmed,
        "unknown": unknown,
        "method": "plex_client_identifier",
    }
    return connections

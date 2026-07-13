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



def annotate_connection_profiles(
    connections: dict[str, Any],
    plex: dict[str, Any],
) -> dict[str, Any]:
    sessions = [
        session
        for session in plex.get("sessions", [])
        if isinstance(session, dict)
    ]

    annotated = dict(connections)

    for collection_name in (
        "public_peers",
        "recent_public_peers",
    ):
        peers = connections.get(collection_name)

        if not isinstance(peers, list):
            continue

        annotated_peers: list[object] = []

        for peer in peers:
            if not isinstance(peer, dict):
                annotated_peers.append(peer)
                continue

            row = dict(peer)
            activity = row.get("activity")

            if not isinstance(activity, dict):
                annotated_peers.append(row)
                continue

            activity_kind = str(
                activity.get("kind") or ""
            ).lower()

            if not activity_kind.startswith("plex"):
                annotated_peers.append(row)
                continue

            profile = correlate_plex_activity(
                activity,
                sessions,
            )

            row["connection_profile"] = {
                "account_name": profile.account_name,
                "account_id": profile.account_id,
                "person_name": profile.person_name,
                "device_name": profile.device_name,
                "client_identifier": profile.client_identifier,
                "service": profile.service,
                "confidence": profile.confidence,
                "evidence": list(profile.evidence),
            }

            annotated_peers.append(row)

        annotated[collection_name] = annotated_peers

    return annotated

from __future__ import annotations

import unittest

from edgewatch.correlation import (
    annotate_connection_profiles,
    correlate_plex_activity,
)


class CorrelationTests(unittest.TestCase):
    def test_exact_client_identifier_confirms_plex_account(self) -> None:
        profile = correlate_plex_activity(
            {
                "client_identifier": "client-abc",
                "device_name": "Living Room Roku",
            },
            [
                {
                    "client_identifier": "client-abc",
                    "user": "Alex",
                    "user_id": "user-42",
                    "player": "Living Room Roku",
                }
            ],
        )

        self.assertEqual(profile.account_name, "Alex")
        self.assertEqual(profile.account_id, "user-42")
        self.assertEqual(profile.person_name, "")
        self.assertEqual(profile.device_name, "Living Room Roku")
        self.assertEqual(profile.confidence, "confirmed")

    def test_username_alone_does_not_identify_person(self) -> None:
        profile = correlate_plex_activity(
            {
                "client_identifier": "",
                "device_name": "Phone",
            },
            [
                {
                    "client_identifier": "other-device",
                    "user": "Shared Account",
                    "user_id": "shared-1",
                    "player": "Phone",
                }
            ],
        )

        self.assertEqual(profile.account_name, "")
        self.assertEqual(profile.person_name, "")
        self.assertEqual(profile.confidence, "unknown")

    def test_duplicate_client_identifier_is_not_overstated(self) -> None:
        profile = correlate_plex_activity(
            {
                "client_identifier": "duplicate-client",
                "device_name": "Unknown device",
            },
            [
                {
                    "client_identifier": "duplicate-client",
                    "user": "Account A",
                    "user_id": "a",
                },
                {
                    "client_identifier": "duplicate-client",
                    "user": "Account B",
                    "user_id": "b",
                },
            ],
        )

        self.assertEqual(profile.account_name, "")
        self.assertEqual(profile.person_name, "")
        self.assertEqual(profile.confidence, "unknown")

    def test_connection_collections_receive_profiles(self) -> None:
        connections = {
            "public_peers": [
                {
                    "ip": "198.51.100.20",
                    "activity": {
                        "kind": "plex_media",
                        "client_identifier": "client-abc",
                        "device_name": "Living Room Roku",
                    },
                }
            ],
            "recent_public_peers": [
                {
                    "ip": "198.51.100.20",
                    "activity": {
                        "kind": "plex",
                        "client_identifier": "client-abc",
                    },
                }
            ],
        }

        plex = {
            "sessions": [
                {
                    "client_identifier": "client-abc",
                    "user": "Alex",
                    "user_id": "user-42",
                    "player": "Living Room Roku",
                }
            ]
        }

        annotated = annotate_connection_profiles(
            connections,
            plex,
        )

        active_profile = annotated["public_peers"][0][
            "connection_profile"
        ]
        recent_profile = annotated["recent_public_peers"][0][
            "connection_profile"
        ]

        self.assertEqual(
            active_profile["account_name"],
            "Alex",
        )
        self.assertEqual(
            active_profile["confidence"],
            "confirmed",
        )
        self.assertEqual(
            recent_profile["client_identifier"],
            "client-abc",
        )

    def test_non_plex_activity_is_not_annotated(self) -> None:
        connections = {
            "public_peers": [
                {
                    "ip": "198.51.100.30",
                    "activity": {
                        "kind": "https",
                        "client_identifier": "client-abc",
                    },
                }
            ]
        }

        annotated = annotate_connection_profiles(
            connections,
            {"sessions": []},
        )

        self.assertNotIn(
            "connection_profile",
            annotated["public_peers"][0],
        )


if __name__ == "__main__":
    unittest.main()

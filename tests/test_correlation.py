from __future__ import annotations

import unittest

from edgewatch.correlation import annotate_connection_profiles, correlate_plex_activity


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
                    "state": "playing",
                }
            ],
        )

        self.assertEqual(profile.confidence, "confirmed")
        self.assertEqual(profile.account_name, "Alex")
        self.assertEqual(profile.account_id, "user-42")
        self.assertEqual(profile.device_name, "Living Room Roku")

    def test_username_alone_does_not_identify_person(self) -> None:
        profile = correlate_plex_activity(
            {"device_name": "Alex's TV"},
            [{"user": "Alex", "player": "Alex's TV", "state": "playing"}],
        )
        self.assertEqual(profile.confidence, "unknown")
        self.assertEqual(profile.account_name, "")
        self.assertEqual(profile.person_name, "")

    def test_duplicate_client_identifier_is_not_overstated(self) -> None:
        sessions = [
            {
                "client_identifier": "duplicate",
                "user": "Alex",
                "state": "playing",
            },
            {
                "client_identifier": "duplicate",
                "user": "Sam",
                "state": "paused",
            },
        ]
        profile = correlate_plex_activity(
            {"client_identifier": "duplicate"},
            sessions,
        )
        self.assertEqual(profile.confidence, "unknown")
        self.assertEqual(profile.account_name, "")

    def test_connection_collections_receive_profiles(self) -> None:
        connections = {
            "public_peers": [
                {
                    "ip": "198.51.100.20",
                    "activity": {
                        "kind": "plex_media",
                        "client_identifier": "client-abc",
                    },
                }
            ],
            "recent_public_peers": [
                {
                    "ip": "198.51.100.20",
                    "activity": {
                        "kind": "plex_media",
                        "client_identifier": "client-abc",
                    },
                }
            ],
        }
        sessions = [
            {
                "client_identifier": "client-abc",
                "user": "Alex",
                "user_id": "user-42",
                "player": "Living Room Roku",
                "state": "playing",
            }
        ]

        result = annotate_connection_profiles(connections, sessions)
        active = result["public_peers"][0]
        recent = result["recent_public_peers"][0]
        self.assertEqual(active["connection_profile"]["confidence"], "confirmed")
        self.assertEqual(recent["connection_profile"]["account_name"], "Alex")
        self.assertEqual(active["display_name"], "Living Room Roku")
        self.assertEqual(result["identity_summary"]["confirmed"], 2)

    def test_non_plex_activity_is_not_annotated(self) -> None:
        connections = {
            "public_peers": [
                {
                    "ip": "198.51.100.20",
                    "activity": {
                        "kind": "edgewatch",
                        "client_identifier": "client-abc",
                    },
                }
            ]
        }
        annotate_connection_profiles(connections, [])
        self.assertNotIn("connection_profile", connections["public_peers"][0])
        self.assertEqual(connections["identity_summary"]["confirmed"], 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from edgewatch.plex import parse_sessions, summarize_plex


class PlexTests(unittest.TestCase):
    def test_transcode_session_parsing(self) -> None:
        payload = {
            "MediaContainer": {
                "Metadata": [{
                    "ratingKey": "42",
                    "type": "episode",
                    "title": "The Test",
                    "parentTitle": "Season 1",
                    "grandparentTitle": "Edge Show",
                    "duration": 3600000,
                    "viewOffset": 1800000,
                    "User": {"id": "user-42", "title": "Alex"},
                    "Player": {
                        "title": "Living Room Roku",
                        "location": "wan",
                        "state": "playing",
                        "secure": True,
                        "machineIdentifier": "client-abc",
                        "playbackId": "playback-123",
                        "playbackSessionId": "playback-session-456",
                        "userID": "user-42",
                    },
                    "Session": {"id": "abc", "bandwidth": 8000},
                    "TranscodeSession": {
                        "videoDecision": "transcode",
                        "audioDecision": "copy",
                        "videoResolution": "1080",
                        "videoCodec": "h264",
                        "audioCodec": "aac",
                    },
                    "Media": [{"videoResolution": "4k", "videoCodec": "hevc", "audioCodec": "eac3"}],
                }]
            }
        }
        sessions = parse_sessions(payload, "Media Node A", now_epoch=100)
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session["user"], "Alex")
        self.assertEqual(session["user_id"], "user-42")
        self.assertEqual(session["client_identifier"], "client-abc")
        self.assertEqual(session["playback_id"], "playback-123")
        self.assertEqual(session["playback_session_id"], "playback-session-456")
        self.assertEqual(session["mode"], "Transcode")
        self.assertEqual(session["progress_percent"], 50.0)
        self.assertEqual(session["bandwidth_kbps"], 8000)
        summary = summarize_plex([{"ok": True, "sessions": sessions}])
        self.assertEqual(summary["active_streams"], 1)
        self.assertEqual(summary["transcode"], 1)

    def test_direct_play_without_transcode(self) -> None:
        payload = {"MediaContainer": {"Metadata": [{
            "title": "Movie",
            "Media": [{"videoDecision": "directplay", "audioDecision": "directplay"}],
        }]}}
        self.assertEqual(parse_sessions(payload, "Media Node B")[0]["mode"], "Direct Play")


if __name__ == "__main__":
    unittest.main()

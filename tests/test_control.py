from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from edgewatch.agent import _attach_acknowledgements, _merged_events
from edgewatch.control import ControlStorage
from edgewatch.storage import Storage


class ControlStorageTests(unittest.TestCase):
    def test_acknowledge_is_idempotent_and_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            control = ControlStorage(Path(folder) / "control.db")
            control.initialize()

            first, changed = control.acknowledge(
                fingerprint="ssh-password-authentication",
                title="SSH password authentication is enabled",
                category="SSH",
                severity="medium",
                actor="alex@example.com",
                now_epoch=1000,
            )
            second, changed_again = control.acknowledge(
                fingerprint="ssh-password-authentication",
                title="SSH password authentication is enabled",
                category="SSH",
                severity="medium",
                actor="other@example.com",
                now_epoch=2000,
            )

            self.assertTrue(changed)
            self.assertFalse(changed_again)
            self.assertTrue(first["active"])
            self.assertEqual(second["acknowledged_by"], "alex@example.com")
            self.assertEqual(second["acknowledged_at"], 1000)
            self.assertEqual(len(control.recent_events()), 1)

    def test_severity_change_resolution_and_recurrence(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            control = ControlStorage(Path(folder) / "control.db")
            control.initialize()
            control.acknowledge(
                fingerprint="finding",
                title="Finding",
                category="Security",
                severity="medium",
                actor="alex@example.com",
                now_epoch=1000,
            )

            created = control.reconcile(
                [{
                    "fingerprint": "finding",
                    "title": "Finding",
                    "category": "Security",
                    "severity": "high",
                }],
                now_epoch=1100,
            )
            self.assertEqual([item["event_type"] for item in created], ["severity_changed"])
            self.assertEqual(control.acknowledgement("finding")["current_severity"], "high")

            resolved = control.reconcile([], now_epoch=1200)
            self.assertEqual([item["event_type"] for item in resolved], ["resolved"])
            self.assertFalse(control.acknowledgement("finding")["active"])

            recurrence, changed = control.acknowledge(
                fingerprint="finding",
                title="Finding",
                category="Security",
                severity="medium",
                actor="alex@example.com",
                now_epoch=1300,
            )
            self.assertTrue(changed)
            self.assertTrue(recurrence["active"])

    def test_resume_records_actor_and_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            control = ControlStorage(Path(folder) / "control.db")
            control.initialize()
            control.acknowledge(
                fingerprint="finding",
                title="Finding",
                category="Security",
                severity="high",
                actor="alex@example.com",
                now_epoch=1000,
            )
            state, changed = control.resume(
                fingerprint="finding",
                actor="paul@example.com",
                now_epoch=1500,
            )
            self.assertTrue(changed)
            self.assertFalse(state["active"])
            self.assertEqual(state["resumed_by"], "paul@example.com")
            self.assertEqual(state["resumed_at"], 1500)

    def test_rollback_journal_mode_and_snapshot_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            control = ControlStorage(base / "control.db")
            control.initialize()
            with control.connect(readonly=True) as connection:
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")

            control.acknowledge(
                fingerprint="finding",
                title="Finding",
                category="Security",
                severity="medium",
                actor="alex@example.com",
                now_epoch=1000,
            )
            snapshot = {
                "posture": {
                    "insights": [{
                        "fingerprint": "finding",
                        "title": "Finding",
                        "category": "Security",
                        "severity": "medium",
                        "score": 10,
                    }]
                }
            }
            _attach_acknowledgements(snapshot, control.controls())
            self.assertTrue(snapshot["posture"]["insights"][0]["acknowledged"])
            self.assertEqual(snapshot["posture"]["acknowledged_findings"], 1)
            self.assertEqual(len(snapshot["acknowledged_findings"]), 1)

    def test_timeline_merge_orders_control_and_security_events(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            storage = Storage(base / "edgewatch.db")
            storage.initialize()
            control = ControlStorage(base / "control.db")
            control.initialize()
            storage.add_event({
                "ts": 1000,
                "severity": "medium",
                "category": "SSH",
                "title": "Finding",
                "detail": "Detected",
                "fingerprint": "finding",
            })
            control.acknowledge(
                fingerprint="finding",
                title="Finding",
                category="SSH",
                severity="medium",
                actor="alex@example.com",
                now_epoch=1100,
            )
            events = _merged_events(storage, control, 10)
            self.assertEqual(events[0]["event_type"], "acknowledged")
            self.assertEqual(events[1]["event_type"], "detected")

    def test_unchanged_reconcile_avoids_control_row_write(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            control = ControlStorage(Path(folder) / "control.db")
            control.initialize()
            control.acknowledge(
                fingerprint="finding",
                title="Finding",
                category="Security",
                severity="medium",
                actor="alex@example.com",
                now_epoch=1000,
            )

            created = control.reconcile(
                [{
                    "fingerprint": "finding",
                    "title": "Finding",
                    "category": "Security",
                    "severity": "medium",
                }],
                now_epoch=2000,
            )

            self.assertEqual(created, [])
            self.assertEqual(control.acknowledgement("finding")["updated_at"], 1000)

    def test_concurrent_acknowledgement_is_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            control = ControlStorage(Path(folder) / "control.db")
            control.initialize()

            def acknowledge(index: int):
                return control.acknowledge(
                    fingerprint="concurrent-finding",
                    title="Concurrent finding",
                    category="Test",
                    severity="medium",
                    actor=f"user-{index}",
                    now_epoch=1000 + index,
                )

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(acknowledge, range(8)))

            self.assertEqual(sum(1 for _, changed in results if changed), 1)
            self.assertTrue(all(bool(row.get("active")) for row, _ in results))
            events = control.recent_events(20)
            self.assertEqual(
                sum(1 for event in events if event["event_type"] == "acknowledged"),
                1,
            )


if __name__ == "__main__":
    unittest.main()

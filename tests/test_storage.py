from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from edgewatch.storage import Storage, atomic_write_json, read_json


class StorageTests(unittest.TestCase):
    def test_round_trip_and_monthly_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "edgewatch.db"
            storage = Storage(path)
            storage.initialize()
            storage.add_sample({
                "ts": 100,
                "cpu_percent": 1,
                "memory_percent": 2,
                "disk_percent": 3,
                "load1": 0.1,
                "rx_bps": 4,
                "tx_bps": 5,
                "established_connections": 6,
                "failed_ssh": 7,
                "risk_score": 8,
            })
            storage.add_traffic("2026-07-10", "eth0", 1000, 2000)
            storage.add_traffic("2026-07-11", "eth0", 3000, 4000)
            self.assertEqual(len(storage.history(0, 10)), 1)
            self.assertEqual(storage.monthly_traffic("2026-07", "eth0"), {"rx_bytes": 4000, "tx_bytes": 6000})


    def test_database_uses_readonly_compatible_journal_mode(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "edgewatch.db"
            storage = Storage(path)
            storage.initialize()
            with storage.connect(readonly=True) as connection:
                mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                self.assertEqual(mode, "delete")

    def test_atomic_json(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "latest.json"
            atomic_write_json(path, {"ok": True})
            self.assertEqual(read_json(path), {"ok": True})


if __name__ == "__main__":
    unittest.main()

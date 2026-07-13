from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS samples (
    ts INTEGER PRIMARY KEY,
    cpu_percent REAL NOT NULL,
    memory_percent REAL NOT NULL,
    disk_percent REAL NOT NULL,
    load1 REAL NOT NULL,
    rx_bps REAL NOT NULL,
    tx_bps REAL NOT NULL,
    established_connections INTEGER NOT NULL,
    failed_ssh INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    plex_streams INTEGER NOT NULL DEFAULT 0,
    public_peers INTEGER NOT NULL DEFAULT 0,
    active_findings INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic_daily (
    day TEXT NOT NULL,
    interface TEXT NOT NULL,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(day, interface)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    fingerprint TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_state (
    fingerprint TEXT PRIMARY KEY,
    active INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    last_seen_ts INTEGER NOT NULL,
    last_notified_ts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    provider TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_fingerprint_ts ON events(fingerprint, ts DESC);
CREATE INDEX IF NOT EXISTS idx_notification_log_ts ON notification_log(ts DESC);
"""


SAMPLE_COLUMNS = {
    "plex_streams": "INTEGER NOT NULL DEFAULT 0",
    "public_peers": "INTEGER NOT NULL DEFAULT 0",
    "active_findings": "INTEGER NOT NULL DEFAULT 0",
}


class Storage:
    def __init__(self, database_path: str | Path):
        self.path = Path(database_path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5.0)
        try:
            connection.executescript(SCHEMA)
            existing = {row[1] for row in connection.execute("PRAGMA table_info(samples)").fetchall()}
            for name, definition in SAMPLE_COLUMNS.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE samples ADD COLUMN {name} {definition}")
            connection.commit()
        finally:
            connection.close()

    @contextmanager
    def connect(self, readonly: bool = False) -> Iterator[sqlite3.Connection]:
        if readonly:
            uri = f"file:{self.path}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=2.0)
        else:
            connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            yield connection
        finally:
            connection.close()

    def add_sample(self, sample: dict[str, object]) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO samples (
                    ts, cpu_percent, memory_percent, disk_percent, load1,
                    rx_bps, tx_bps, established_connections, failed_ssh, risk_score,
                    plex_streams, public_peers, active_findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(sample["ts"]),
                    float(sample["cpu_percent"]),
                    float(sample["memory_percent"]),
                    float(sample["disk_percent"]),
                    float(sample["load1"]),
                    float(sample["rx_bps"]),
                    float(sample["tx_bps"]),
                    int(sample["established_connections"]),
                    int(sample["failed_ssh"]),
                    int(sample["risk_score"]),
                    int(sample.get("plex_streams", 0)),
                    int(sample.get("public_peers", 0)),
                    int(sample.get("active_findings", 0)),
                ),
            )
            connection.commit()

    def add_traffic(self, day: str, interface: str, rx_bytes: int, tx_bytes: int) -> None:
        if rx_bytes < 0 or tx_bytes < 0:
            return
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO traffic_daily(day, interface, rx_bytes, tx_bytes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(day, interface) DO UPDATE SET
                    rx_bytes = traffic_daily.rx_bytes + excluded.rx_bytes,
                    tx_bytes = traffic_daily.tx_bytes + excluded.tx_bytes
                """,
                (day, interface, int(rx_bytes), int(tx_bytes)),
            )
            connection.commit()

    def add_event(self, event: dict[str, object], repeat_seconds: int = 300) -> bool:
        ts = int(event["ts"])
        fingerprint = str(event["fingerprint"])
        with self.connect() as connection:
            row = connection.execute(
                "SELECT ts FROM events WHERE fingerprint = ? ORDER BY ts DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row is not None and ts - int(row["ts"]) < repeat_seconds:
                return False
            connection.execute(
                """
                INSERT INTO events(ts, severity, category, title, detail, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    str(event["severity"]),
                    str(event["category"]),
                    str(event["title"]),
                    str(event["detail"]),
                    fingerprint,
                ),
            )
            connection.commit()
        return True

    def history(self, since_ts: int, limit: int) -> list[dict[str, object]]:
        with self.connect(readonly=True) as connection:
            rows = connection.execute(
                """
                SELECT * FROM (
                    SELECT ts, cpu_percent, memory_percent, disk_percent, load1,
                           rx_bps, tx_bps, established_connections, failed_ssh, risk_score,
                           plex_streams, public_peers, active_findings
                    FROM samples
                    WHERE ts >= ?
                    ORDER BY ts DESC
                    LIMIT ?
                ) recent
                ORDER BY ts ASC
                """,
                (int(since_ts), int(limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_events(self, limit: int = 75) -> list[dict[str, object]]:
        with self.connect(readonly=True) as connection:
            rows = connection.execute(
                """
                SELECT ts, severity, category, title, detail, fingerprint,
                       'detected' AS event_type, '' AS actor
                FROM events
                ORDER BY ts DESC, id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def monthly_traffic(self, month_prefix: str, interface: str) -> dict[str, int]:
        with self.connect(readonly=True) as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(rx_bytes), 0) AS rx_bytes,
                       COALESCE(SUM(tx_bytes), 0) AS tx_bytes
                FROM traffic_daily
                WHERE day LIKE ? AND interface = ?
                """,
                (f"{month_prefix}%", interface),
            ).fetchone()
        return {"rx_bytes": int(row["rx_bytes"]), "tx_bytes": int(row["tx_bytes"])}

    def alert_states(self) -> dict[str, dict[str, object]]:
        with self.connect(readonly=True) as connection:
            rows = connection.execute("SELECT * FROM alert_state").fetchall()
        return {str(row["fingerprint"]): dict(row) for row in rows}

    def upsert_alert_state(
        self,
        fingerprint: str,
        active: bool,
        severity: str,
        title: str,
        last_seen_ts: int,
        last_notified_ts: int,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO alert_state(fingerprint, active, severity, title, last_seen_ts, last_notified_ts)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    active=excluded.active,
                    severity=excluded.severity,
                    title=excluded.title,
                    last_seen_ts=excluded.last_seen_ts,
                    last_notified_ts=excluded.last_notified_ts
                """,
                (fingerprint, int(active), severity, title, int(last_seen_ts), int(last_notified_ts)),
            )
            connection.commit()

    def add_notification_log(
        self, ts: int, provider: str, fingerprint: str, success: bool, detail: str
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO notification_log(ts, provider, fingerprint, success, detail)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(ts), provider, fingerprint, int(success), detail[:500]),
            )
            connection.commit()

    def notification_summary(self) -> dict[str, object]:
        with self.connect(readonly=True) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0) AS sent,
                       MAX(ts) AS last_ts
                FROM notification_log
                """
            ).fetchone()
        return {
            "total": int(row["total"]),
            "sent": int(row["sent"]),
            "last_ts": int(row["last_ts"]) if row["last_ts"] is not None else None,
        }

    def prune(self, retention_days: int) -> None:
        cutoff = int((datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp())
        day_cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days + 2)).date().isoformat()
        notification_cutoff = int((datetime.now(timezone.utc) - timedelta(days=max(30, retention_days))).timestamp())
        with self.connect() as connection:
            connection.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            connection.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            connection.execute("DELETE FROM traffic_daily WHERE day < ?", (day_cutoff,))
            connection.execute("DELETE FROM notification_log WHERE ts < ?", (notification_cutoff,))
            connection.commit()


def atomic_write_json(path: str | Path, payload: dict[str, object], mode: int = 0o640) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, destination)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temp_name)
        raise


def read_json(path: str | Path) -> dict[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Snapshot must be a JSON object")
    return data

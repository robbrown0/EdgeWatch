from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

CONTROL_SCHEMA = """
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS finding_acknowledgements (
    fingerprint TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    acknowledged_severity TEXT NOT NULL,
    current_severity TEXT NOT NULL,
    acknowledged_at INTEGER NOT NULL,
    acknowledged_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    resolved_at INTEGER,
    resumed_at INTEGER,
    resumed_by TEXT
);

CREATE TABLE IF NOT EXISTS acknowledgement_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_acknowledgement_active
    ON finding_acknowledgements(active, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_acknowledgement_events_ts
    ON acknowledgement_events(ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_acknowledgement_events_fingerprint_ts
    ON acknowledgement_events(fingerprint, ts DESC, id DESC);
"""


class ControlStorage:
    """Persistent, narrowly scoped dashboard control state.

    The control database is intentionally separate from the collector history
    database. The unprivileged web service may write only this database, while
    the collector retains exclusive write ownership of monitoring history.
    Rollback-journal mode keeps the tiny, low-write control store compatible
    with supported Ubuntu SQLite builds without relying on WAL concurrency.
    """

    def __init__(self, database_path: str | Path):
        self.path = Path(database_path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(CONTROL_SCHEMA)
            connection.commit()

    @contextmanager
    def connect(self, readonly: bool = False) -> Iterator[sqlite3.Connection]:
        if readonly:
            connection = sqlite3.connect(
                f"file:{self.path}?mode=ro",
                uri=True,
                timeout=5.0,
            )
        else:
            connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, object] | None:
        if row is None:
            return None
        payload = dict(row)
        payload["active"] = bool(payload.get("active"))
        return payload

    def controls(self) -> dict[str, dict[str, object]]:
        with self.connect(readonly=True) as connection:
            rows = connection.execute(
                """
                SELECT fingerprint, title, category, acknowledged_severity,
                       current_severity, acknowledged_at, acknowledged_by,
                       updated_at, active, resolved_at, resumed_at, resumed_by
                FROM finding_acknowledgements
                ORDER BY updated_at DESC, fingerprint ASC
                """
            ).fetchall()
        return {
            str(row["fingerprint"]): self._row(row) or {}
            for row in rows
        }

    def active_acknowledgements(self) -> dict[str, dict[str, object]]:
        with self.connect(readonly=True) as connection:
            rows = connection.execute(
                """
                SELECT fingerprint, title, category, acknowledged_severity,
                       current_severity, acknowledged_at, acknowledged_by,
                       updated_at, active, resolved_at, resumed_at, resumed_by
                FROM finding_acknowledgements
                WHERE active = 1
                ORDER BY acknowledged_at ASC, fingerprint ASC
                """
            ).fetchall()
        return {
            str(row["fingerprint"]): self._row(row) or {}
            for row in rows
        }

    def acknowledgement(self, fingerprint: str) -> dict[str, object] | None:
        with self.connect(readonly=True) as connection:
            row = connection.execute(
                """
                SELECT fingerprint, title, category, acknowledged_severity,
                       current_severity, acknowledged_at, acknowledged_by,
                       updated_at, active, resolved_at, resumed_at, resumed_by
                FROM finding_acknowledgements
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()
        return self._row(row)

    def acknowledge(
        self,
        *,
        fingerprint: str,
        title: str,
        category: str,
        severity: str,
        actor: str,
        now_epoch: int,
    ) -> tuple[dict[str, object], bool]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM finding_acknowledgements WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

            if existing is not None and bool(existing["active"]):
                connection.commit()
                return self._row(existing) or {}, False

            connection.execute(
                """
                INSERT INTO finding_acknowledgements(
                    fingerprint, title, category, acknowledged_severity,
                    current_severity, acknowledged_at, acknowledged_by,
                    updated_at, active, resolved_at, resumed_at, resumed_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL, NULL)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    title=excluded.title,
                    category=excluded.category,
                    acknowledged_severity=excluded.acknowledged_severity,
                    current_severity=excluded.current_severity,
                    acknowledged_at=excluded.acknowledged_at,
                    acknowledged_by=excluded.acknowledged_by,
                    updated_at=excluded.updated_at,
                    active=1,
                    resolved_at=NULL,
                    resumed_at=NULL,
                    resumed_by=NULL
                """,
                (
                    fingerprint,
                    title,
                    category,
                    severity,
                    severity,
                    int(now_epoch),
                    actor,
                    int(now_epoch),
                ),
            )

            self._insert_event(
                connection,
                ts=now_epoch,
                severity="info",
                category="Acknowledgement",
                title=f"Acknowledged and muted: {title}",
                detail=(
                    f"{actor} acknowledged this active {severity} finding. "
                    "Repeat timeline entries and push notifications are muted until "
                    "alerts are resumed or the finding resolves."
                ),
                fingerprint=fingerprint,
                event_type="acknowledged",
                actor=actor,
            )

            row = connection.execute(
                "SELECT * FROM finding_acknowledgements WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            connection.commit()

        return self._row(row) or {}, True

    def resume(
        self,
        *,
        fingerprint: str,
        actor: str,
        now_epoch: int,
    ) -> tuple[dict[str, object] | None, bool]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM finding_acknowledgements WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None, False

            changed = bool(row["active"])
            if changed:
                connection.execute(
                    """
                    UPDATE finding_acknowledgements
                    SET active = 0,
                        updated_at = ?,
                        resumed_at = ?,
                        resumed_by = ?,
                        resolved_at = NULL
                    WHERE fingerprint = ?
                    """,
                    (int(now_epoch), int(now_epoch), actor, fingerprint),
                )
                self._insert_event(
                    connection,
                    ts=now_epoch,
                    severity="info",
                    category="Acknowledgement",
                    title=f"Alerts resumed: {row['title']}",
                    detail=(
                        f"{actor} resumed timeline and push alerts for this finding. "
                        "If the condition remains active, EdgeWatch will evaluate it for "
                        "notification on the next collector cycle."
                    ),
                    fingerprint=fingerprint,
                    event_type="resumed",
                    actor=actor,
                )

            updated = connection.execute(
                "SELECT * FROM finding_acknowledgements WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            connection.commit()

        return self._row(updated), changed

    def reconcile(
        self,
        insights: list[dict[str, object]],
        now_epoch: int,
    ) -> list[dict[str, object]]:
        """Update acknowledged findings for current severity and resolution.

        Returns lifecycle events created during this reconciliation.
        """
        current = {
            str(item.get("fingerprint")): item
            for item in insights
            if item.get("fingerprint")
        }
        created: list[dict[str, object]] = []

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM finding_acknowledgements WHERE active = 1"
            ).fetchall()

            for row in rows:
                fingerprint = str(row["fingerprint"])
                item = current.get(fingerprint)
                if item is None:
                    connection.execute(
                        """
                        UPDATE finding_acknowledgements
                        SET active = 0,
                            updated_at = ?,
                            resolved_at = ?,
                            resumed_at = NULL,
                            resumed_by = NULL
                        WHERE fingerprint = ?
                        """,
                        (int(now_epoch), int(now_epoch), fingerprint),
                    )
                    event = {
                        "ts": int(now_epoch),
                        "severity": "low",
                        "category": "Acknowledgement",
                        "title": f"Acknowledged finding resolved: {row['title']}",
                        "detail": (
                            "The condition is no longer present in the current assessment. "
                            "Its acknowledgement was cleared so a future recurrence will alert normally."
                        ),
                        "fingerprint": fingerprint,
                        "event_type": "resolved",
                        "actor": "EdgeWatch",
                    }
                    self._insert_event(connection, **event)
                    created.append(event)
                    continue

                severity = str(item.get("severity") or row["current_severity"] or "info")
                title = str(item.get("title") or row["title"] or "Finding")
                category = str(item.get("category") or row["category"] or "General")
                previous_severity = str(row["current_severity"] or "info")

                metadata_changed = (
                    title != str(row["title"])
                    or category != str(row["category"])
                    or severity != previous_severity
                )
                if metadata_changed:
                    connection.execute(
                        """
                        UPDATE finding_acknowledgements
                        SET title = ?, category = ?, current_severity = ?, updated_at = ?
                        WHERE fingerprint = ?
                        """,
                        (title, category, severity, int(now_epoch), fingerprint),
                    )

                if severity != previous_severity:
                    event = {
                        "ts": int(now_epoch),
                        "severity": severity,
                        "category": "Acknowledgement",
                        "title": f"Acknowledged finding severity changed: {title}",
                        "detail": (
                            f"Severity changed from {previous_severity} to {severity}. "
                            "The finding remains acknowledged and push notifications remain muted."
                        ),
                        "fingerprint": fingerprint,
                        "event_type": "severity_changed",
                        "actor": "EdgeWatch",
                    }
                    self._insert_event(connection, **event)
                    created.append(event)

            connection.commit()

        return created

    def prune(self, retention_days: int) -> None:
        cutoff = int(
            (
                datetime.now(timezone.utc)
                - timedelta(days=max(30, retention_days))
            ).timestamp()
        )
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM acknowledgement_events WHERE ts < ?",
                (cutoff,),
            )
            connection.execute(
                """
                DELETE FROM finding_acknowledgements
                WHERE active = 0 AND updated_at < ?
                """,
                (cutoff,),
            )
            connection.commit()

    def recent_events(self, limit: int = 75) -> list[dict[str, object]]:
        with self.connect(readonly=True) as connection:
            rows = connection.execute(
                """
                SELECT ts, severity, category, title, detail, fingerprint,
                       event_type, actor
                FROM acknowledgement_events
                ORDER BY ts DESC, id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection,
        *,
        ts: int,
        severity: str,
        category: str,
        title: str,
        detail: str,
        fingerprint: str,
        event_type: str,
        actor: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO acknowledgement_events(
                ts, severity, category, title, detail,
                fingerprint, event_type, actor
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(ts),
                severity,
                category,
                title,
                detail,
                fingerprint,
                event_type,
                actor,
            ),
        )

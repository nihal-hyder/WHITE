"""SQLite storage for local-only mode, server-side sessions and domain verification.

The database file lives in WHITE_DATA_DIR (default ~/.white/white.db) and is excluded from Git.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from white.database.base import RepositoryError, ScanRecord
from white.scanner.models import ScanReport, ScanState

SCHEMA = [
    # version 1
    """
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        target_url TEXT NOT NULL,
        hostname TEXT NOT NULL,
        state TEXT NOT NULL,
        active_checks INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        finished_at TEXT,
        findings_total INTEGER NOT NULL DEFAULT 0,
        high_priority INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        report_json TEXT
    );
    CREATE INDEX IF NOT EXISTS scans_owner_created ON scans (owner_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS sessions (
        id_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        token_blob TEXT NOT NULL,
        access_expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        purpose TEXT NOT NULL DEFAULT 'login'
    );
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);
    CREATE TABLE IF NOT EXISTS domains (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at TEXT NOT NULL,
        verified_at TEXT,
        method TEXT,
        UNIQUE (owner_id, hostname)
    );
    """,
]


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class SQLiteDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            for index, script in enumerate(SCHEMA[version:], start=version + 1):
                conn.executescript(script)
                conn.execute(f"PRAGMA user_version = {index}")

    @contextlib.contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        except sqlite3.Error as exc:
            raise RepositoryError("The local database could not be accessed.") from exc
        finally:
            conn.close()


class SQLiteScanRepository:
    """Local-only scan history. Every query is filtered by owner_id."""

    def __init__(self, db: SQLiteDatabase) -> None:
        self.db = db

    def create_scan(self, owner_id: str, record: ScanRecord) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, owner_id, target_url, hostname, state, active_checks, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    owner_id,
                    record.target_url,
                    record.hostname,
                    record.state.value,
                    int(record.active_checks),
                    _iso(record.created_at),
                ),
            )

    def save_report(self, owner_id: str, scan_id: str, report: ScanReport) -> None:
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET state = ?, finished_at = ?, findings_total = ?, high_priority = ?,"
                " error = ?, report_json = ? WHERE id = ? AND owner_id = ?",
                (
                    report.state.value,
                    _iso(report.finished_at),
                    report.summary.findings_total,
                    report.summary.severity_counts.high_priority,
                    "; ".join(report.errors)[:1000] or None,
                    report.model_dump_json(),
                    scan_id,
                    owner_id,
                ),
            )
            if cur.rowcount != 1:
                raise RepositoryError("Scan record not found.")

    def mark_state(self, owner_id: str, scan_id: str, state: ScanState, error: str | None = None) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE scans SET state = ?, error = COALESCE(?, error),"
                " finished_at = CASE WHEN ? THEN ? ELSE finished_at END WHERE id = ? AND owner_id = ?",
                (
                    state.value,
                    error,
                    state.value not in {"queued", "running"},
                    _iso(datetime.now(UTC)),
                    scan_id,
                    owner_id,
                ),
            )

    def _record(self, row: sqlite3.Row, with_report: bool) -> ScanRecord:
        report = None
        if with_report and row["report_json"]:
            report = ScanReport.model_validate(json.loads(row["report_json"]))
        return ScanRecord(
            id=row["id"],
            owner_id=row["owner_id"],
            target_url=row["target_url"],
            hostname=row["hostname"],
            state=ScanState(row["state"]),
            created_at=_dt(row["created_at"]),
            active_checks=bool(row["active_checks"]),  # type: ignore[arg-type]
            finished_at=_dt(row["finished_at"]),
            findings_total=row["findings_total"],
            high_priority=row["high_priority"],
            error=row["error"],
            report=report,
        )

    def get_scan(self, owner_id: str, scan_id: str) -> ScanRecord | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ? AND owner_id = ?", (scan_id, owner_id)
            ).fetchone()
        return self._record(row, True) if row else None

    def list_scans(self, owner_id: str, limit: int = 100) -> list[ScanRecord]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT id, owner_id, target_url, hostname, state, active_checks, created_at, finished_at,"
                " findings_total, high_priority, error, NULL AS report_json FROM scans"
                " WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?",
                (owner_id, limit),
            ).fetchall()
        return [self._record(r, False) for r in rows]

    def list_reports(self, owner_id: str, target_url: str | None = None, limit: int = 50) -> list[ScanReport]:
        query = "SELECT * FROM scans WHERE owner_id = ? AND report_json IS NOT NULL"
        params: list = [owner_id]
        if target_url:
            query += " AND target_url = ?"
            params.append(target_url)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self.db.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [r for r in (self._record(row, True).report for row in rows) if r is not None]

    def delete_scan(self, owner_id: str, scan_id: str) -> bool:
        with self.db.connect() as conn:
            cur = conn.execute(
                "DELETE FROM scans WHERE id = ? AND owner_id = ? AND state NOT IN ('queued','running')",
                (scan_id, owner_id),
            )
        return cur.rowcount == 1

    def mark_interrupted(self) -> int:
        """Called at startup: scans that were running when the server stopped did not finish."""
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET state = 'interrupted', error = 'The server stopped before the scan finished.'"
                " WHERE state IN ('queued', 'running')"
            )
        return cur.rowcount

"""Domain ownership verification (DNS TXT record or a well-known verification file).

Verification state is stored server-side (local SQLite), not in a table users can write to
through the Supabase API, so it cannot be forged by calling the database directly.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import dns.exception
import dns.resolver

from white.database.base import RepositoryError
from white.database.sqlite import SQLiteDatabase
from white.scanner.http import SafeHttpClient
from white.scanner.models import ScanConfig
from white.scanner.netsafety import TargetValidationError, validate_target_url

TXT_PREFIX = "_white-verify"
FILE_PATH = "/.well-known/white-verify.txt"


@dataclass
class DomainRecord:
    id: str
    owner_id: str
    hostname: str
    token: str
    created_at: datetime
    verified_at: datetime | None
    method: str | None

    @property
    def txt_name(self) -> str:
        return f"{TXT_PREFIX}.{self.hostname}"

    @property
    def txt_value(self) -> str:
        return f"white-verify={self.token}"

    @property
    def file_url(self) -> str:
        return f"https://{self.hostname}{FILE_PATH}"


def normalize_hostname(value: str, config: ScanConfig) -> str:
    raw = value.strip().lower()
    if "://" not in raw:
        raw = "https://" + raw
    return validate_target_url(raw, config).host


class DomainStore:
    def __init__(self, db: SQLiteDatabase) -> None:
        self.db = db

    @staticmethod
    def _record(row) -> DomainRecord:
        return DomainRecord(
            id=row["id"],
            owner_id=row["owner_id"],
            hostname=row["hostname"],
            token=row["token"],
            created_at=datetime.fromisoformat(row["created_at"]),
            verified_at=datetime.fromisoformat(row["verified_at"]) if row["verified_at"] else None,
            method=row["method"],
        )

    def add(self, owner_id: str, hostname: str) -> DomainRecord:
        existing = self.get_by_host(owner_id, hostname)
        if existing:
            return existing
        record_id = str(uuid.uuid4())
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO domains (id, owner_id, hostname, token, created_at) VALUES (?, ?, ?, ?, ?)",
                (record_id, owner_id, hostname, secrets.token_hex(16), datetime.now(UTC).isoformat()),
            )
        record = self.get(owner_id, record_id)
        assert record is not None
        return record

    def get(self, owner_id: str, record_id: str) -> DomainRecord | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM domains WHERE id = ? AND owner_id = ?", (record_id, owner_id)
            ).fetchone()
        return self._record(row) if row else None

    def get_by_host(self, owner_id: str, hostname: str) -> DomainRecord | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM domains WHERE owner_id = ? AND hostname = ?", (owner_id, hostname)
            ).fetchone()
        return self._record(row) if row else None

    def list(self, owner_id: str) -> list[DomainRecord]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domains WHERE owner_id = ? ORDER BY hostname", (owner_id,)
            ).fetchall()
        return [self._record(r) for r in rows]

    def delete(self, owner_id: str, record_id: str) -> bool:
        with self.db.connect() as conn:
            cur = conn.execute("DELETE FROM domains WHERE id = ? AND owner_id = ?", (record_id, owner_id))
        return cur.rowcount == 1

    def mark_verified(self, owner_id: str, record_id: str, method: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE domains SET verified_at = ?, method = ? WHERE id = ? AND owner_id = ?",
                (datetime.now(UTC).isoformat(), method, record_id, owner_id),
            )

    def is_authorized(self, owner_id: str, hostname: str) -> bool:
        """True if the host was verified by file, or it or a parent domain was verified by DNS."""
        hostname = hostname.lower()
        for record in self.list(owner_id):
            if record.verified_at is None:
                continue
            if record.hostname == hostname:
                return True
            if record.method == "dns" and hostname.endswith("." + record.hostname):
                return True
        return False


def check_dns(record: DomainRecord, timeout: float = 5.0) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(record.txt_name, "TXT")
    except (dns.exception.DNSException, OSError):
        return False
    for answer in answers:
        value = b"".join(answer.strings).decode("utf-8", errors="replace").strip()
        if secrets.compare_digest(value, record.txt_value):
            return True
    return False


def check_file(record: DomainRecord, config: ScanConfig) -> bool:
    try:
        validate_target_url(record.file_url, config)
    except TargetValidationError:
        return False
    with SafeHttpClient(config.model_copy(update={"max_requests": 3, "max_scan_seconds": 20})) as client:
        result = client.fetch(record.file_url, follow_redirects=False)
    if not result.ok or result.status_code != 200:
        return False
    return secrets.compare_digest(result.text.strip()[:200], record.token)


def verify(store: DomainStore, record: DomainRecord, config: ScanConfig) -> str | None:
    """Try DNS then file verification. Returns the method used, or None."""
    if check_dns(record):
        store.mark_verified(record.owner_id, record.id, "dns")
        return "dns"
    if check_file(record, config):
        store.mark_verified(record.owner_id, record.id, "file")
        return "file"
    return None


__all__ = [
    "DomainRecord",
    "DomainStore",
    "RepositoryError",
    "check_dns",
    "check_file",
    "verify",
    "normalize_hostname",
    "TXT_PREFIX",
    "FILE_PATH",
]

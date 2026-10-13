"""Domain verification records stored in Supabase, for serverless hosting.

Users can write to their own rows through the public Supabase API (Row Level Security allows
it), so a row alone must never be trusted. When WHITE verifies a domain it stores an HMAC
signature computed with WHITE_SECRET_KEY over (user, hostname, method, verified_at). Only
rows with a valid signature count as verified; a row a user inserts or edits by hand does not.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from white.auth.domains import DomainRecord
from white.database.base import RepositoryError
from white.database.supabase import SessionExpiredError

COLUMNS = "id,user_id,hostname,token,created_at,verified_at,method,signature"


def _sign(secret: str, owner_id: str, hostname: str, method: str, verified_at: str) -> str:
    # Sign epoch seconds rather than the text: PostgreSQL may reformat timestamps on output.
    epoch = int(datetime.fromisoformat(verified_at).timestamp())
    message = f"white-domain|{owner_id}|{hostname}|{method}|{epoch}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class SupabaseDomainStore:
    def __init__(
        self,
        url: str,
        publishable_key: str,
        token_supplier: Callable[[], str],
        secret: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base = f"{url}/rest/v1/verified_domains"
        self._key = publishable_key
        self._token = token_supplier
        self._secret = secret
        self._transport = transport

    def _request(
        self, method: str, *, params: dict | None = None, json: Any = None, prefer: str | None = None
    ) -> list[dict]:
        headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
        }
        if prefer:
            headers["Prefer"] = prefer
        try:
            with httpx.Client(timeout=15, transport=self._transport, trust_env=False) as client:
                response = client.request(method, self._base, params=params, json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise RepositoryError("Could not reach the Supabase database.") from exc
        if response.status_code == 401:
            raise SessionExpiredError("Your session has expired. Please sign in again.")
        if response.status_code >= 400:
            raise RepositoryError(f"The database rejected the request (HTTP {response.status_code}).")
        if not response.content:
            return []
        data = response.json()
        return data if isinstance(data, list) else []

    def _record(self, row: dict) -> DomainRecord:
        verified_at = None
        method = row.get("method")
        if row.get("verified_at") and method and row.get("signature"):
            try:
                expected = _sign(self._secret, row["user_id"], row["hostname"], method, row["verified_at"])
            except ValueError:
                expected = ""
            if expected and hmac.compare_digest(expected, row["signature"]):
                verified_at = datetime.fromisoformat(row["verified_at"])
        return DomainRecord(
            id=row["id"],
            owner_id=row["user_id"],
            hostname=row["hostname"],
            token=row["token"],
            created_at=datetime.fromisoformat(row["created_at"]),
            verified_at=verified_at,
            method=method if verified_at else None,
        )

    @staticmethod
    def _valid_id(value: str) -> bool:
        try:
            uuid.UUID(value)
        except (ValueError, TypeError):
            return False
        return True

    def add(self, owner_id: str, hostname: str) -> DomainRecord:
        existing = self.get_by_host(owner_id, hostname)
        if existing:
            return existing
        rows = self._request(
            "POST",
            json={
                "id": str(uuid.uuid4()),
                "user_id": owner_id,
                "hostname": hostname,
                "token": secrets.token_hex(16),
                "created_at": datetime.now(UTC).isoformat(),
            },
            prefer="return=representation",
        )
        return self._record(rows[0])

    def get(self, owner_id: str, record_id: str) -> DomainRecord | None:
        if not self._valid_id(record_id):
            return None
        rows = self._request(
            "GET", params={"id": f"eq.{record_id}", "user_id": f"eq.{owner_id}", "select": COLUMNS}
        )
        return self._record(rows[0]) if rows else None

    def get_by_host(self, owner_id: str, hostname: str) -> DomainRecord | None:
        rows = self._request(
            "GET", params={"hostname": f"eq.{hostname}", "user_id": f"eq.{owner_id}", "select": COLUMNS}
        )
        return self._record(rows[0]) if rows else None

    def list(self, owner_id: str) -> list[DomainRecord]:
        rows = self._request(
            "GET", params={"user_id": f"eq.{owner_id}", "select": COLUMNS, "order": "hostname.asc"}
        )
        return [self._record(r) for r in rows]

    def delete(self, owner_id: str, record_id: str) -> bool:
        if not self._valid_id(record_id):
            return False
        rows = self._request(
            "DELETE",
            params={"id": f"eq.{record_id}", "user_id": f"eq.{owner_id}"},
            prefer="return=representation",
        )
        return len(rows) == 1

    def mark_verified(self, owner_id: str, record_id: str, method: str) -> None:
        record = self.get(owner_id, record_id)
        if record is None:
            raise RepositoryError("Domain not found.")
        verified_at = datetime.now(UTC).replace(microsecond=0).isoformat()
        signature = _sign(self._secret, owner_id, record.hostname, method, verified_at)
        self._request(
            "PATCH",
            params={"id": f"eq.{record_id}", "user_id": f"eq.{owner_id}"},
            json={"verified_at": verified_at, "method": method, "signature": signature},
            prefer="return=minimal",
        )

    def is_authorized(self, owner_id: str, hostname: str) -> bool:
        hostname = hostname.lower()
        for record in self.list(owner_id):
            if record.verified_at is None:
                continue
            if record.hostname == hostname or (
                record.method == "dns" and hostname.endswith("." + record.hostname)
            ):
                return True
        return False

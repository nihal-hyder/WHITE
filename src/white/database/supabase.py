"""Supabase (PostgREST) scan repository.

Requests are made with the signed-in user's own access token and the public publishable key,
so PostgreSQL Row Level Security enforces ownership in the database. No service-role key is
used anywhere. Owner filters are also applied in every query as defence in depth.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from white.database.base import RepositoryError, ScanRecord
from white.scanner.models import ScanReport, ScanState

LIST_COLUMNS = (
    "id,user_id,target_url,hostname,state,active_checks,created_at,finished_at,"
    "findings_total,high_priority,error,started_at"
)
INLINE_COLUMNS = ",progress,cancel_requested"  # added by migration 20261013095149


class SessionExpiredError(RepositoryError):
    pass


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (ValueError, TypeError):
        return False
    return True


class SupabaseScanRepository:
    def __init__(
        self,
        url: str,
        publishable_key: str,
        token_supplier: Callable[[], str],
        *,
        transport: httpx.BaseTransport | None = None,
        inline_columns: bool = False,
    ) -> None:
        self._columns = LIST_COLUMNS + (INLINE_COLUMNS if inline_columns else "")
        self._base = f"{url}/rest/v1"
        self._key = publishable_key
        self._token = token_supplier
        self._transport = transport

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: Any = None,
        prefer: str | None = None,
    ) -> httpx.Response:
        headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
        }
        if prefer:
            headers["Prefer"] = prefer
        try:
            with httpx.Client(timeout=15, transport=self._transport, trust_env=False) as client:
                response = client.request(
                    method, f"{self._base}/{path}", params=params, json=json, headers=headers
                )
        except httpx.HTTPError as exc:
            raise RepositoryError("Could not reach the Supabase database.") from exc
        if response.status_code == 401:
            raise SessionExpiredError("Your session has expired. Please sign in again.")
        if response.status_code >= 400:
            raise RepositoryError(f"The database rejected the request (HTTP {response.status_code}).")
        return response

    @staticmethod
    def _record(row: dict) -> ScanRecord:
        report = ScanReport.model_validate(row["report"]) if row.get("report") else None
        return ScanRecord(
            id=row["id"],
            owner_id=row["user_id"],
            target_url=row["target_url"],
            hostname=row["hostname"],
            state=ScanState(row["state"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            active_checks=bool(row.get("active_checks")),
            finished_at=datetime.fromisoformat(row["finished_at"]) if row.get("finished_at") else None,
            findings_total=row.get("findings_total") or 0,
            high_priority=row.get("high_priority") or 0,
            error=row.get("error"),
            report=report,
            started_at=datetime.fromisoformat(row["started_at"]) if row.get("started_at") else None,
            progress=row.get("progress") if isinstance(row.get("progress"), dict) else None,
            cancel_requested=bool(row.get("cancel_requested")),
        )

    def create_scan(self, owner_id: str, record: ScanRecord) -> None:
        self._request(
            "POST",
            "scans",
            json={
                "id": record.id,
                "user_id": owner_id,
                "target_url": record.target_url,
                "hostname": record.hostname,
                "state": record.state.value,
                "active_checks": record.active_checks,
                "created_at": record.created_at.isoformat(),
            },
            prefer="return=minimal",
        )

    def save_report(self, owner_id: str, scan_id: str, report: ScanReport) -> None:
        if not _is_uuid(scan_id):
            raise RepositoryError("Invalid scan ID.")
        sev = report.summary.severity_counts
        updated = self._request(
            "PATCH",
            "scans",
            params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}"},
            json={
                "state": report.state.value,
                "started_at": report.started_at.isoformat(),
                "finished_at": report.finished_at.isoformat() if report.finished_at else None,
                "duration_seconds": report.duration_seconds,
                "findings_total": report.summary.findings_total,
                "high_priority": sev.high_priority,
                "severity_counts": sev.model_dump(),
                "error": "; ".join(report.errors)[:1000] or None,
                "schema_version": report.schema_version,
                "report": report.model_dump(mode="json"),
            },
            prefer="return=representation",
        ).json()
        if len(updated) != 1:
            raise RepositoryError("Scan record not found.")
        self._request("DELETE", "findings", params={"scan_id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}"})
        rows = [
            {
                "scan_id": scan_id,
                "user_id": owner_id,
                "fingerprint": f.id,
                "check_id": f.check_id,
                "check_version": f.check_version,
                "title": f.title,
                "category": f.category.value,
                "status": f.status.value,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "affected_url": f.affected_url,
            }
            for f in report.findings
        ]
        if rows:
            self._request("POST", "findings", json=rows, prefer="return=minimal")

    def mark_state(self, owner_id: str, scan_id: str, state: ScanState, error: str | None = None) -> None:
        if not _is_uuid(scan_id):
            return
        body: dict[str, Any] = {"state": state.value}
        if error:
            body["error"] = error[:1000]
        if state.value not in {"queued", "running"}:
            body["finished_at"] = datetime.now().astimezone().isoformat()
        self._request(
            "PATCH",
            "scans",
            params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}"},
            json=body,
            prefer="return=minimal",
        )

    def get_scan(self, owner_id: str, scan_id: str) -> ScanRecord | None:
        if not _is_uuid(scan_id):
            return None
        rows = self._request(
            "GET",
            "scans",
            params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}", "select": self._columns + ",report"},
        ).json()
        return self._record(rows[0]) if rows else None

    def list_scans(self, owner_id: str, limit: int = 100) -> list[ScanRecord]:
        rows = self._request(
            "GET",
            "scans",
            params={
                "user_id": f"eq.{owner_id}",
                "select": self._columns,
                "order": "created_at.desc",
                "limit": str(limit),
            },
        ).json()
        return [self._record(r) for r in rows]

    def list_reports(self, owner_id: str, target_url: str | None = None, limit: int = 50) -> list[ScanReport]:
        params = {
            "user_id": f"eq.{owner_id}",
            "report": "not.is.null",
            "select": self._columns + ",report",
            "order": "created_at.desc",
            "limit": str(limit),
        }
        if target_url:
            params["target_url"] = f"eq.{target_url}"
        rows = self._request("GET", "scans", params=params).json()
        return [r.report for r in (self._record(row) for row in rows) if r.report is not None]

    def delete_scan(self, owner_id: str, scan_id: str) -> bool:
        if not _is_uuid(scan_id):
            return False
        rows = self._request(
            "DELETE",
            "scans",
            params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}", "state": "not.in.(queued,running)"},
            prefer="return=representation",
        ).json()
        return len(rows) == 1

    # --- inline execution -------------------------------------------------------------------
    def claim_scan(self, owner_id: str, scan_id: str) -> bool:
        if not _is_uuid(scan_id):
            return False
        rows = self._request(
            "PATCH",
            "scans",
            params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}", "state": "eq.queued"},
            json={"state": "running", "started_at": datetime.now().astimezone().isoformat()},
            prefer="return=representation",
        ).json()
        return len(rows) == 1

    def update_progress(self, owner_id: str, scan_id: str, progress: dict) -> None:
        if _is_uuid(scan_id):
            self._request(
                "PATCH",
                "scans",
                params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}"},
                json={"progress": progress},
                prefer="return=minimal",
            )

    def request_cancel(self, owner_id: str, scan_id: str) -> bool:
        if not _is_uuid(scan_id):
            return False
        rows = self._request(
            "PATCH",
            "scans",
            params={"id": f"eq.{scan_id}", "user_id": f"eq.{owner_id}", "state": "in.(queued,running)"},
            json={"cancel_requested": True},
            prefer="return=representation",
        ).json()
        return len(rows) == 1

    def count_scans_since(self, owner_id: str, since: datetime, states: set[str] | None = None) -> int:
        params = {"user_id": f"eq.{owner_id}", "created_at": f"gte.{since.isoformat()}", "select": "id"}
        if states:
            params["state"] = f"in.({','.join(sorted(states))})"
        return len(self._request("GET", "scans", params=params).json())

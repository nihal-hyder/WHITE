"""Repository interface for scan persistence. Every method is scoped to an owner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from white.scanner.models import ScanReport, ScanState


class RepositoryError(Exception):
    """Persistence failed. The message is safe to show to users."""


@dataclass
class ScanRecord:
    id: str
    owner_id: str
    target_url: str
    hostname: str
    state: ScanState
    created_at: datetime
    active_checks: bool = False
    finished_at: datetime | None = None
    findings_total: int = 0
    high_priority: int = 0
    error: str | None = None
    report: ScanReport | None = None


class ScanRepository(Protocol):
    def create_scan(self, owner_id: str, record: ScanRecord) -> None: ...

    def save_report(self, owner_id: str, scan_id: str, report: ScanReport) -> None: ...

    def mark_state(self, owner_id: str, scan_id: str, state: ScanState, error: str | None = None) -> None: ...

    def get_scan(self, owner_id: str, scan_id: str) -> ScanRecord | None: ...

    def list_scans(self, owner_id: str, limit: int = 100) -> list[ScanRecord]: ...

    def list_reports(
        self, owner_id: str, target_url: str | None = None, limit: int = 50
    ) -> list[ScanReport]: ...

    def delete_scan(self, owner_id: str, scan_id: str) -> bool: ...

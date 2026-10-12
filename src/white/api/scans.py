"""Scan operations shared by the HTML routes and the JSON API."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from white.api.deps import CurrentUser, Services
from white.api.jobs import JobRejected
from white.database.base import RepositoryError, ScanRecord
from white.reporting import analytics
from white.scanner.models import FINISHED_STATES, ScanReport, ScanState
from white.scanner.netsafety import TargetValidationError, normalize_user_url, validate_target_url


class ScanRequestError(Exception):
    def __init__(self, message: str, status_code: int = 400, code: str = "invalid") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def start_scan(
    svc: Services, user: CurrentUser, raw_url: str, *, authorized: bool, active_checks: bool
) -> str:
    if not authorized:
        raise ScanRequestError(
            "Please confirm that you own this website or are authorized to assess it.", code="authorization"
        )
    config = svc.settings.scan_config(active_checks=active_checks)
    try:
        target = validate_target_url(normalize_user_url(raw_url), config)
    except TargetValidationError as exc:
        raise ScanRequestError(str(exc), code="target") from exc
    if svc.settings.domain_verification_required and not svc.domains.is_authorized(user.id, target.host):
        raise ScanRequestError(
            f"Ownership of {target.host} has not been verified. Add and verify the domain on the "
            "Domains page before scanning it.",
            status_code=403,
            code="domain_unverified",
        )
    scan_id = str(uuid.uuid4())
    try:
        job = svc.jobs.reserve(user.id, target.url, scan_id)
    except JobRejected as exc:
        raise ScanRequestError(str(exc), status_code=exc.status_code, code="limit") from exc
    repo = svc.repo_for(user)
    try:
        repo.create_scan(
            user.id,
            ScanRecord(
                id=scan_id,
                owner_id=user.id,
                target_url=target.url,
                hostname=target.host,
                state=ScanState.QUEUED,
                created_at=datetime.now(UTC),
                active_checks=active_checks,
            ),
        )
    except RepositoryError as exc:
        svc.jobs.release(job)
        raise ScanRequestError(str(exc), status_code=503, code="storage") from exc

    def on_save(report: ScanReport) -> None:
        repo.save_report(user.id, scan_id, report)

    def on_fail(state: ScanState, message: str) -> None:
        repo.mark_state(user.id, scan_id, state, message)

    svc.jobs.start(job, config, on_save, on_fail)
    return scan_id


def get_record(svc: Services, user: CurrentUser, scan_id: str) -> ScanRecord | None:
    try:
        uuid.UUID(scan_id)
    except ValueError:
        return None
    return svc.repo_for(user).get_scan(user.id, scan_id)


def status_payload(svc: Services, user: CurrentUser, record: ScanRecord) -> dict:
    job = svc.jobs.get(record.id, user.id)
    if job is not None and (job.state not in FINISHED_STATES or record.state not in FINISHED_STATES):
        return job.to_status()
    state = record.state
    if state in {ScanState.QUEUED, ScanState.RUNNING}:
        # Not tracked by this server process: it was interrupted by a restart.
        state = ScanState.INTERRUPTED
    report = record.report
    return {
        "scan_id": record.id,
        "state": state.value,
        "stage": "Finished" if state in FINISHED_STATES else state.value,
        "completed_checks": len(report.checks) if report else 0,
        "total_checks": len(report.checks) if report else 0,
        "elapsed_seconds": report.duration_seconds if report else None,
        "error": record.error
        or ("The server stopped before this scan finished." if state == ScanState.INTERRUPTED else None),
        "live": False,
    }


def comparison_for(svc: Services, user: CurrentUser, report: ScanReport) -> analytics.Comparison:
    history = svc.repo_for(user).list_reports(user.id, target_url=report.target_url, limit=50)
    return analytics.compare(report, analytics.find_previous(report, history))


def download_name(report: ScanReport, ext: str) -> str:
    host = re.sub(r"[^A-Za-z0-9.-]", "_", report.hostname)[:80]
    return f"white-report-{host}-{report.started_at:%Y%m%d-%H%M}.{ext}"


def dashboard_data(svc: Services, user: CurrentUser, target: str | None) -> dict:
    """All dashboard numbers, computed from the user's stored reports only."""
    repo = svc.repo_for(user)
    records = repo.list_scans(user.id, limit=200)
    targets: list[str] = []
    for r in records:
        if r.target_url not in targets:
            targets.append(r.target_url)
    finished = [r for r in records if r.state in {ScanState.COMPLETED, ScanState.COMPLETED_WITH_ERRORS}]
    if target not in targets:
        target = finished[0].target_url if finished else (targets[0] if targets else None)
    data: dict = {"targets": targets, "target": target, "total_scans": len(records), "latest": None}
    if target is None:
        return data
    history = repo.list_reports(user.id, target_url=target, limit=50)
    completed = sorted(
        [r for r in history if r.state in analytics.COMPARABLE_STATES],
        key=lambda r: r.started_at,
        reverse=True,
    )
    latest_any = max(history, key=lambda r: r.started_at, default=None)
    data["latest_attempt"] = (
        {
            "scan_id": latest_any.scan_id,
            "state": latest_any.state.value,
            "date": latest_any.started_at.isoformat(),
        }
        if latest_any
        else None
    )
    if not completed:
        return data
    latest = completed[0]
    previous = completed[1] if len(completed) > 1 else None
    comparison = analytics.compare(latest, previous)
    s = latest.summary
    data.update(
        {
            "latest": {
                "scan_id": latest.scan_id,
                "hostname": latest.hostname,
                "state": latest.state.value,
                "date": latest.started_at.isoformat(),
                "date_label": latest.started_at.strftime("%d %b %Y, %H:%M UTC"),
                "findings_total": s.findings_total,
                "high_priority": s.severity_counts.high_priority,
                "checks_total": s.checks_total,
                "checks_completed": s.checks_total
                - s.status_counts.get("NOT_TESTED", 0)
                - s.status_counts.get("ERROR", 0),
                "assessment": analytics.overall_assessment(latest)[0],
                "tone": analytics.overall_assessment(latest)[1],
                "summary": analytics.executive_summary(latest),
            },
            "previous": (
                {
                    "scan_id": previous.scan_id,
                    "findings_total": previous.summary.findings_total,
                    "high_priority": previous.summary.severity_counts.high_priority,
                    "date_label": previous.started_at.strftime("%d %b %Y"),
                }
                if previous
                else None
            ),
            "comparison": comparison.counts() if comparison.available else None,
            "severity": analytics.severity_chart(latest),
            "categories": analytics.category_chart(latest),
            "coverage": analytics.coverage_chart(latest),
            "trend": analytics.trend_chart(history),
            "actions": analytics.prioritized_actions(latest),
        }
    )
    return data

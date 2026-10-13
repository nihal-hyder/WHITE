"""Scan operations shared by the HTML routes and the JSON API."""

from __future__ import annotations

import logging
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta

from white.api.deps import CurrentUser, Services
from white.api.jobs import JobRejected
from white.database.base import RepositoryError, ScanRecord
from white.reporting import analytics
from white.scanner.engine import Progress
from white.scanner.models import FINISHED_STATES, ScanReport, ScanState
from white.scanner.netsafety import TargetValidationError, normalize_user_url, validate_target_url

log = logging.getLogger("white.scans")
QUEUED_STALE_SECONDS = 600


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
    if svc.settings.domain_verification_required and not svc.domains_for(user).is_authorized(
        user.id, target.host
    ):
        raise ScanRequestError(
            f"Ownership of {target.host} has not been verified. Add and verify the domain on the "
            "Domains page before scanning it.",
            status_code=403,
            code="domain_unverified",
        )
    scan_id = str(uuid.uuid4())
    if svc.settings.execution_mode == "inline":
        return _create_inline(svc, user, scan_id, target.url, target.host, active_checks)
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


def _create_inline(
    svc: Services, user: CurrentUser, scan_id: str, url: str, host: str, active_checks: bool
) -> str:
    """Serverless: only record the scan here. The browser then calls run_scan_inline()."""
    repo = svc.repo_for(user)
    now = datetime.now(UTC)
    active_window = now - timedelta(seconds=svc.settings.max_scan_seconds + QUEUED_STALE_SECONDS)
    if repo.count_scans_since(user.id, active_window, {"queued", "running"}) > 0:
        raise ScanRequestError(
            "You already have a scan in progress. Wait for it to finish or cancel it.",
            status_code=409,
            code="limit",
        )
    if repo.count_scans_since(user.id, now - timedelta(hours=1)) >= svc.settings.scans_per_user_per_hour:
        raise ScanRequestError(
            "You have reached the hourly scan limit. Please try again later.", status_code=429, code="limit"
        )
    try:
        repo.create_scan(
            user.id,
            ScanRecord(
                id=scan_id,
                owner_id=user.id,
                target_url=url,
                hostname=host,
                state=ScanState.QUEUED,
                created_at=now,
                active_checks=active_checks,
            ),
        )
    except RepositoryError as exc:
        raise ScanRequestError(str(exc), status_code=503, code="storage") from exc
    return scan_id


def run_scan_inline(svc: Services, user: CurrentUser, scan_id: str) -> dict:
    """Run a queued scan inside the current request (serverless hosting).

    Progress and cancellation go through the database so any server instance can report them.
    Claiming is atomic (queued -> running), so a scan can only ever run once.
    """
    record = get_record(svc, user, scan_id)
    if record is None:
        raise ScanRequestError("Scan not found.", status_code=404, code="not_found")
    repo = svc.repo_for(user)
    if not repo.claim_scan(user.id, scan_id):
        raise ScanRequestError("This scan has already started or finished.", status_code=409, code="claimed")
    config = svc.settings.scan_config(active_checks=record.active_checks)
    cancel = threading.Event()

    def on_progress(p: Progress) -> None:
        try:
            current = repo.get_scan(user.id, scan_id)
            if current is not None and current.cancel_requested:
                cancel.set()
            repo.update_progress(
                user.id, scan_id, {"stage": p.stage, "completed": p.completed, "total": p.total}
            )
        except Exception:  # noqa: BLE001 - progress reporting must never break the scan
            log.warning("could not record progress for scan %s", scan_id)

    try:
        report = svc.jobs.scanner_factory(config).run(
            record.target_url, scan_id=scan_id, progress=on_progress, cancel_event=cancel
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("inline scan %s crashed", scan_id)
        repo.mark_state(
            user.id, scan_id, ScanState.FAILED, f"The scan could not run: {exc.__class__.__name__}"
        )
        raise ScanRequestError("The scan could not run.", status_code=500, code="failed") from exc
    repo.save_report(user.id, scan_id, report)
    updated = repo.get_scan(user.id, scan_id)
    return (
        status_payload(svc, user, updated) if updated else {"scan_id": scan_id, "state": report.state.value}
    )


def cancel_scan(svc: Services, user: CurrentUser, record: ScanRecord) -> bool:
    if svc.settings.execution_mode != "inline":
        return svc.jobs.cancel(record.id, user.id)
    repo = svc.repo_for(user)
    if record.state == ScanState.QUEUED:
        repo.mark_state(user.id, record.id, ScanState.CANCELLED, "Cancelled before it started.")
        return True
    return repo.request_cancel(user.id, record.id)


def _inline_is_stale(svc: Services, record: ScanRecord) -> bool:
    now = datetime.now(UTC)
    if record.state == ScanState.RUNNING:
        started = record.started_at or record.created_at
        return (now - started).total_seconds() > svc.settings.max_scan_seconds + 120
    return (now - record.created_at).total_seconds() > QUEUED_STALE_SECONDS


def prepare_delete(svc: Services, user: CurrentUser, record: ScanRecord) -> None:
    """Allow deleting inline scans that were abandoned (they would otherwise stay 'running')."""
    if (
        svc.settings.execution_mode == "inline"
        and record.state in {ScanState.QUEUED, ScanState.RUNNING}
        and _inline_is_stale(svc, record)
    ):
        svc.repo_for(user).mark_state(user.id, record.id, ScanState.INTERRUPTED, "The scan did not finish.")


def get_record(svc: Services, user: CurrentUser, scan_id: str) -> ScanRecord | None:
    try:
        uuid.UUID(scan_id)
    except ValueError:
        return None
    return svc.repo_for(user).get_scan(user.id, scan_id)


def status_payload(svc: Services, user: CurrentUser, record: ScanRecord) -> dict:
    if (
        svc.settings.execution_mode == "inline"
        and record.state in {ScanState.QUEUED, ScanState.RUNNING}
        and not _inline_is_stale(svc, record)
    ):
        progress = record.progress or {}
        started = record.started_at
        return {
            "scan_id": record.id,
            "state": record.state.value,
            "stage": progress.get("stage")
            or ("Waiting to start" if record.state == ScanState.QUEUED else "Starting"),
            "completed_checks": int(progress.get("completed") or 0),
            "total_checks": int(progress.get("total") or 0),
            "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 1) if started else 0.0,
            "error": None,
            "live": True,
            "run_required": record.state == ScanState.QUEUED,
        }
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

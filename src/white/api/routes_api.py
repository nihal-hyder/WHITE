"""JSON API. Every route except /api/health requires an authenticated user and enforces ownership."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from white import __version__
from white.api.deps import CurrentUser, require_api_user, services, verify_csrf
from white.api.scans import (
    ScanRequestError,
    dashboard_data,
    download_name,
    get_record,
    start_scan,
    status_payload,
)
from white.reporting.html_report import build_html
from white.reporting.json_report import to_json
from white.reporting.pdf_report import build_pdf
from white.scanner.models import FINISHED_STATES

router = APIRouter(prefix="/api", tags=["api"])


class ScanCreate(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = Field(description="Confirms the caller owns or may assess the website.")
    active_checks: bool = False


class ScanSummaryOut(BaseModel):
    scan_id: str
    target_url: str
    hostname: str
    state: str
    created_at: str
    finished_at: str | None
    findings_total: int
    high_priority: int


@router.get("/health")
def health(request: Request) -> dict:
    svc = services(request)
    return {"status": "ok", "version": __version__, "mode": svc.settings.auth_mode}


def _record_or_404(request: Request, user: CurrentUser, scan_id: str):
    record = get_record(services(request), user, scan_id)
    if record is None:
        # Same response for "missing" and "belongs to someone else" - no information leak.
        raise HTTPException(status_code=404, detail="Scan not found.")
    return record


@router.get("/scans", response_model=list[ScanSummaryOut])
def list_scans(request: Request, user: CurrentUser = Depends(require_api_user)) -> list[ScanSummaryOut]:
    records = services(request).repo_for(user).list_scans(user.id)
    return [
        ScanSummaryOut(
            scan_id=r.id,
            target_url=r.target_url,
            hostname=r.hostname,
            state=r.state.value,
            created_at=r.created_at.isoformat(),
            finished_at=r.finished_at.isoformat() if r.finished_at else None,
            findings_total=r.findings_total,
            high_priority=r.high_priority,
        )
        for r in records
    ]


@router.post("/scans", status_code=202, dependencies=[Depends(verify_csrf)])
def create_scan(body: ScanCreate, request: Request, user: CurrentUser = Depends(require_api_user)):
    try:
        scan_id = start_scan(
            services(request), user, body.url, authorized=body.authorized, active_checks=body.active_checks
        )
    except ScanRequestError as exc:
        return JSONResponse({"detail": str(exc), "code": exc.code}, status_code=exc.status_code)
    return {"scan_id": scan_id, "status_url": f"/api/scans/{scan_id}/status", "page_url": f"/scans/{scan_id}"}


@router.get("/scans/{scan_id}/status")
def scan_status(scan_id: str, request: Request, user: CurrentUser = Depends(require_api_user)) -> dict:
    record = _record_or_404(request, user, scan_id)
    return status_payload(services(request), user, record)


@router.get("/scans/{scan_id}")
def scan_detail(scan_id: str, request: Request, user: CurrentUser = Depends(require_api_user)) -> dict:
    record = _record_or_404(request, user, scan_id)
    return {
        "status": status_payload(services(request), user, record),
        "report": record.report.model_dump(mode="json") if record.report else None,
    }


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: str, request: Request, user: CurrentUser = Depends(require_api_user)
) -> list[dict]:
    record = _record_or_404(request, user, scan_id)
    if record.report is None:
        raise HTTPException(status_code=409, detail="The scan has not finished yet.")
    return [f.model_dump(mode="json") for f in record.report.findings]


@router.post("/scans/{scan_id}/cancel", dependencies=[Depends(verify_csrf)])
def cancel_scan(scan_id: str, request: Request, user: CurrentUser = Depends(require_api_user)) -> dict:
    _record_or_404(request, user, scan_id)
    if not services(request).jobs.cancel(scan_id, user.id):
        raise HTTPException(status_code=409, detail="This scan is not running.")
    return {"cancelling": True}


@router.delete("/scans/{scan_id}", dependencies=[Depends(verify_csrf)])
def delete_scan(scan_id: str, request: Request, user: CurrentUser = Depends(require_api_user)) -> dict:
    record = _record_or_404(request, user, scan_id)
    if record.state not in FINISHED_STATES and services(request).jobs.get(scan_id, user.id):
        raise HTTPException(status_code=409, detail="Cancel the scan before deleting it.")
    if not services(request).repo_for(user).delete_scan(user.id, scan_id):
        raise HTTPException(status_code=409, detail="The scan could not be deleted.")
    return {"deleted": True}


def report_response(report, fmt: str, comparison=None) -> Response:
    if fmt == "json":
        body, media = to_json(report).encode(), "application/json"
    elif fmt == "html":
        body, media = build_html(report, comparison).encode(), "text/html; charset=utf-8"
    else:
        body, media = build_pdf(report, comparison), "application/pdf"
    return Response(
        body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{download_name(report, fmt)}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/scans/{scan_id}/report.{fmt}")
def scan_report(
    scan_id: str,
    fmt: Literal["json", "pdf", "html"],
    request: Request,
    user: CurrentUser = Depends(require_api_user),
) -> Response:
    record = _record_or_404(request, user, scan_id)
    if record.report is None:
        raise HTTPException(status_code=409, detail="The scan has not finished yet.")
    from white.api.scans import comparison_for

    return report_response(record.report, fmt, comparison_for(services(request), user, record.report))


@router.get("/dashboard")
def dashboard(
    request: Request, target: str | None = None, user: CurrentUser = Depends(require_api_user)
) -> dict:
    return dashboard_data(services(request), user, target)

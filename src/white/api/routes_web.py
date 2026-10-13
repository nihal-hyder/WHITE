"""Server-rendered GUI pages. Protected pages require a signed-in user (or local mode)."""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from white.api.deps import CurrentUser, optional_user, require_user, services, verify_csrf
from white.api.routes_api import report_response
from white.api.scans import (
    ScanRequestError,
    comparison_for,
    dashboard_data,
    get_record,
    start_scan,
    status_payload,
)
from white.auth import domains as domain_service
from white.reporting import analytics
from white.scanner.models import FINISHED_STATES, SEVERITY_ORDER
from white.scanner.netsafety import TargetValidationError
from white.scanner.registry import all_checks

router = APIRouter(tags=["web"])


def render(request: Request, name: str, context: dict, status_code: int = 200) -> Response:
    return request.app.state.templates.TemplateResponse(request, name, context, status_code=status_code)


def _json_for_script(data: object) -> str:
    """JSON safe to embed inside <script type="application/json"> (no '</script>' breakout)."""
    return (
        json.dumps(data, default=str).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    )


@router.get("/")
def landing(request: Request) -> Response:
    user = optional_user(request)
    checks = list(all_checks())
    return render(request, "landing.html", {"user": user, "checks": checks})


PUBLIC_PAGES = {
    "/security": ("security.html", "security"),
    "/privacy": ("privacy.html", "privacy"),
    "/acceptable-use": ("acceptable_use.html", "acceptable-use"),
}


def _public_page(template: str, active: str):
    def page(request: Request) -> Response:
        return render(request, template, {"user": optional_user(request), "active": active})

    return page


for _path, (_template, _active) in PUBLIC_PAGES.items():
    router.add_api_route(_path, _public_page(_template, _active), methods=["GET"], include_in_schema=False)


@router.get("/dashboard")
def dashboard(
    request: Request, target: str | None = None, user: CurrentUser = Depends(require_user)
) -> Response:
    data = dashboard_data(services(request), user, target)
    return render(
        request,
        "dashboard.html",
        {"user": user, "data": data, "chart_json": _json_for_script(data), "active": "dashboard"},
    )


def _new_scan_context(request: Request, user: CurrentUser, **extra) -> dict:
    svc = services(request)
    verified = (
        [d for d in svc.domains.list(user.id) if d.verified_at]
        if svc.settings.domain_verification_required
        else []
    )
    return {
        "user": user,
        "active": "new",
        "checks": all_checks(),
        "verified_domains": verified,
        "url": "",
        "error": None,
        **extra,
    }


@router.get("/scans/new")
def new_scan_page(request: Request, url: str = "", user: CurrentUser = Depends(require_user)) -> Response:
    return render(request, "scan_new.html", _new_scan_context(request, user, url=url[:2048]))


@router.post("/scans", dependencies=[Depends(verify_csrf)])
def create_scan(
    request: Request,
    url: str = Form(""),
    authorized: str | None = Form(None),
    active_checks: str | None = Form(None),
    user: CurrentUser = Depends(require_user),
) -> Response:
    try:
        scan_id = start_scan(
            services(request), user, url, authorized=authorized == "yes", active_checks=active_checks == "yes"
        )
    except ScanRequestError as exc:
        return render(
            request,
            "scan_new.html",
            _new_scan_context(
                request,
                user,
                url=url[:2048],
                error=str(exc),
                error_code=exc.code,
                active_checked=active_checks == "yes",
            ),
            status_code=exc.status_code,
        )
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _record_or_404(request: Request, user: CurrentUser, scan_id: str):
    record = get_record(services(request), user, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return record


@router.get("/scans/{scan_id}")
def scan_page(scan_id: str, request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    svc = services(request)
    record = _record_or_404(request, user, scan_id)
    status = status_payload(svc, user, record)
    if record.report is None:
        return render(
            request,
            "scan_progress.html",
            {
                "user": user,
                "record": record,
                "status": status,
                "finished": status["state"] in {s.value for s in FINISHED_STATES},
                "active": "history",
            },
        )
    report = record.report
    comparison = comparison_for(svc, user, report)
    groups = [(sev, [f for f in report.findings if f.severity == sev]) for sev in SEVERITY_ORDER]
    label, tone = analytics.overall_assessment(report)
    return render(
        request,
        "scan_report.html",
        {
            "user": user,
            "record": record,
            "report": report,
            "groups": groups,
            "assessment": label,
            "tone": tone,
            "summary_text": analytics.executive_summary(report),
            "actions": analytics.prioritized_actions(report),
            "comparison": comparison,
            "new_ids": {f.id for f in comparison.new} if comparison.available else set(),
            "chart_json": _json_for_script(
                {
                    "severity": analytics.severity_chart(report),
                    "categories": analytics.category_chart(report),
                    "coverage": analytics.coverage_chart(report),
                }
            ),
            "active": "history",
        },
    )


@router.get("/scans/{scan_id}/findings/{finding_id}")
def finding_page(
    scan_id: str, finding_id: str, request: Request, user: CurrentUser = Depends(require_user)
) -> Response:
    record = _record_or_404(request, user, scan_id)
    if record.report is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding = next((f for f in record.report.findings if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return render(
        request,
        "finding.html",
        {"user": user, "record": record, "report": record.report, "finding": finding, "active": "history"},
    )


@router.get("/scans/{scan_id}/report.{fmt}")
def download(
    scan_id: str,
    fmt: Literal["json", "pdf", "html"],
    request: Request,
    user: CurrentUser = Depends(require_user),
) -> Response:
    record = _record_or_404(request, user, scan_id)
    if record.report is None:
        raise HTTPException(status_code=409, detail="The scan has not finished yet.")
    return report_response(record.report, fmt, comparison_for(services(request), user, record.report))


@router.post("/scans/{scan_id}/cancel", dependencies=[Depends(verify_csrf)])
def cancel(scan_id: str, request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    _record_or_404(request, user, scan_id)
    services(request).jobs.cancel(scan_id, user.id)
    return RedirectResponse(f"/scans/{scan_id}?msg=scan_cancelled", status_code=303)


@router.post("/scans/{scan_id}/delete", dependencies=[Depends(verify_csrf)])
def delete(scan_id: str, request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    svc = services(request)
    record = _record_or_404(request, user, scan_id)
    job = svc.jobs.get(scan_id, user.id)
    if job is not None and job.state.value in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Cancel the scan before deleting it.")
    if not svc.repo_for(user).delete_scan(user.id, record.id):
        raise HTTPException(status_code=409, detail="The scan could not be deleted.")
    return RedirectResponse("/history?msg=scan_deleted", status_code=303)


@router.get("/history")
def history(request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    svc = services(request)
    records = svc.repo_for(user).list_scans(user.id, limit=200)
    rows = []
    for r in records:
        state = r.state.value
        if state in {"queued", "running"} and svc.jobs.get(r.id, user.id) is None:
            state = "interrupted"
        rows.append({"record": r, "state": state})
    return render(request, "history.html", {"user": user, "rows": rows, "active": "history"})


def render_settings(
    request: Request, user: CurrentUser, error: str | None = None, status_code: int = 200
) -> Response:
    svc = services(request)
    return render(
        request,
        "settings.html",
        {
            "user": user,
            "active": "settings",
            "error": error,
            "settings": svc.settings,
            "scan_count": len(svc.repo_for(user).list_scans(user.id, limit=1000)),
        },
        status_code=status_code,
    )


@router.get("/settings")
def settings_page(request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    return render_settings(request, user)


# ---------------------------------------------------------------- domain verification
@router.get("/domains")
def domains_page(request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    svc = services(request)
    return render(
        request,
        "domains.html",
        {
            "user": user,
            "active": "domains",
            "domains": svc.domains.list(user.id),
            "error": None,
            "file_path": domain_service.FILE_PATH,
        },
    )


@router.post("/domains", dependencies=[Depends(verify_csrf)])
def add_domain(
    request: Request, hostname: str = Form(""), user: CurrentUser = Depends(require_user)
) -> Response:
    svc = services(request)
    try:
        host = domain_service.normalize_hostname(hostname, svc.settings.scan_config())
    except TargetValidationError as exc:
        return render(
            request,
            "domains.html",
            {
                "user": user,
                "active": "domains",
                "error": str(exc),
                "domains": svc.domains.list(user.id),
                "file_path": domain_service.FILE_PATH,
            },
            status_code=400,
        )
    if len(svc.domains.list(user.id)) >= 50:
        raise HTTPException(status_code=429, detail="Domain limit reached.")
    svc.domains.add(user.id, host)
    return RedirectResponse("/domains?msg=domain_added", status_code=303)


@router.post("/domains/{domain_id}/verify", dependencies=[Depends(verify_csrf)])
def verify_domain(domain_id: str, request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    svc = services(request)
    record = svc.domains.get(user.id, domain_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Domain not found.")
    method = domain_service.verify(svc.domains, record, svc.settings.scan_config())
    return RedirectResponse(
        f"/domains?msg={'domain_verified' if method else 'domain_not_verified'}", status_code=303
    )


@router.post("/domains/{domain_id}/delete", dependencies=[Depends(verify_csrf)])
def delete_domain(domain_id: str, request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    if not services(request).domains.delete(user.id, domain_id):
        raise HTTPException(status_code=404, detail="Domain not found.")
    return RedirectResponse("/domains?msg=domain_deleted", status_code=303)

"""Operator admin console at /admin. Gated by a username/password separate from user accounts."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from white.api.admin_data import AdminData
from white.api.deps import client_ip, services, verify_csrf
from white.auth.admin import ADMIN_COOKIE, ADMIN_SESSION_LIFETIME

router = APIRouter(tags=["admin"])


def _render(request: Request, name: str, context: dict, status_code: int = 200) -> Response:
    ctx = {"user": None, "admin_area": True, **context}
    return request.app.state.templates.TemplateResponse(request, name, ctx, status_code=status_code)


def _require_enabled(request: Request):
    admin = services(request).admin
    if admin is None:
        raise HTTPException(status_code=404, detail="Not found.")
    return admin


def _is_admin(request: Request) -> bool:
    admin = services(request).admin
    return admin is not None and admin.session_valid(request.cookies.get(ADMIN_COOKIE))


@router.get("/admin/login")
def admin_login_page(request: Request) -> Response:
    _require_enabled(request)
    if _is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    return _render(request, "admin/login.html", {"error": None})


@router.post("/admin/login", dependencies=[Depends(verify_csrf)])
def admin_login(request: Request, username: str = Form(""), password: str = Form("")) -> Response:
    svc = services(request)
    admin = _require_enabled(request)
    if not svc.admin_limiter.hit(client_ip(request)):
        return _render(
            request,
            "admin/login.html",
            {"error": "Too many attempts. Please wait a few minutes and try again."},
            status_code=429,
        )
    if not admin.verify(username, password):
        return _render(request, "admin/login.html", {"error": "Incorrect username or password."}, 401)
    svc.admin_limiter.reset(client_ip(request))
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        ADMIN_COOKIE,
        admin.create_session(),
        httponly=True,
        samesite="lax",
        secure=svc.settings.secure_cookies,
        path="/admin",
        max_age=ADMIN_SESSION_LIFETIME,
    )
    return response


@router.post("/admin/logout", dependencies=[Depends(verify_csrf)])
def admin_logout(request: Request) -> Response:
    _require_enabled(request)
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie(ADMIN_COOKIE, path="/admin")
    return response


@router.get("/admin")
def admin_dashboard(request: Request) -> Response:
    _require_enabled(request)
    if not _is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    data = AdminData(services(request)).overview()
    return _render(request, "admin/dashboard.html", {"data": data})

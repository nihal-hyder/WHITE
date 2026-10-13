"""Account routes backed by Supabase Auth: sign up, sign in/out, email confirmation, password reset."""

from __future__ import annotations

import contextlib
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from white.api.deps import (
    CurrentUser,
    Services,
    client_ip,
    optional_user,
    require_user,
    services,
    verify_csrf,
)
from white.api.security import SESSION_COOKIE
from white.auth.supabase_auth import AuthError

router = APIRouter(tags=["auth"])
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
MIN_PASSWORD = 8


def _render(request: Request, name: str, context: dict, status_code: int = 200) -> Response:
    return request.app.state.templates.TemplateResponse(request, name, context, status_code=status_code)


def safe_next(value: str | None, default: str = "/dashboard") -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return default
    return value


def _set_session_cookie(response: Response, svc: Services, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=svc.settings.secure_cookies,
        path="/",
        max_age=7 * 24 * 3600,
    )


def _client_key(request: Request, email: str = "") -> str:
    return f"{client_ip(request)}|{email.lower()}"


def _password_problem(password: str, confirm: str) -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Use a password of at least {MIN_PASSWORD} characters."
    if len(password) > 128:
        return "The password is too long (maximum 128 characters)."
    if password != confirm:
        return "The two passwords do not match."
    return None


def _local_mode_redirect(svc: Services) -> Response | None:
    if not svc.settings.supabase_enabled:
        return RedirectResponse("/dashboard", status_code=303)
    return None


@router.get("/login")
def login_page(request: Request, next: str | None = None) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    if optional_user(request) is not None:
        return RedirectResponse(safe_next(next), status_code=303)
    return _render(request, "auth/login.html", {"user": None, "next": safe_next(next), "email": ""})


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login(
    request: Request, email: str = Form(""), password: str = Form(""), next: str = Form("")
) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    email = email.strip()
    context = {"user": None, "next": safe_next(next), "email": email}
    if not EMAIL_RE.match(email) or not password:
        return _render(
            request, "auth/login.html", {**context, "error": "Enter your email and password."}, 400
        )
    if not svc.login_limiter.hit(_client_key(request, email)):
        return _render(
            request,
            "auth/login.html",
            {**context, "error": "Too many sign-in attempts. Please wait 15 minutes and try again."},
            429,
        )
    assert svc.auth is not None
    try:
        session = svc.auth.sign_in(email, password)
    except AuthError as exc:
        context["unconfirmed"] = exc.code == "email_not_confirmed"
        return _render(request, "auth/login.html", {**context, "error": str(exc)}, 400)
    svc.login_limiter.reset(_client_key(request, email))
    response = RedirectResponse(safe_next(next), status_code=303)
    _set_session_cookie(response, svc, svc.sessions.create(session))
    return response


@router.get("/signup")
def signup_page(request: Request) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    if optional_user(request) is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return _render(request, "auth/signup.html", {"user": None, "email": ""})


@router.post("/signup", dependencies=[Depends(verify_csrf)])
def signup(
    request: Request, email: str = Form(""), password: str = Form(""), confirm_password: str = Form("")
) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    email = email.strip()
    context = {"user": None, "email": email}
    if not EMAIL_RE.match(email):
        return _render(request, "auth/signup.html", {**context, "error": "Enter a valid email address."}, 400)
    problem = _password_problem(password, confirm_password)
    if problem:
        return _render(request, "auth/signup.html", {**context, "error": problem}, 400)
    if not svc.email_limiter.hit(_client_key(request)):
        return _render(
            request,
            "auth/signup.html",
            {**context, "error": "Too many requests. Please wait and try again."},
            429,
        )
    assert svc.auth is not None
    try:
        result = svc.auth.sign_up(email, password, f"{svc.settings.site_url}/auth/callback")
    except AuthError as exc:
        return _render(request, "auth/signup.html", {**context, "error": str(exc)}, 400)
    if result.session is not None:
        response = RedirectResponse("/dashboard?msg=confirmed", status_code=303)
        _set_session_cookie(response, svc, svc.sessions.create(result.session))
        return response
    return _render(request, "auth/check_email.html", {"user": None, "email": email, "kind": "signup"})


@router.post("/resend-confirmation", dependencies=[Depends(verify_csrf)])
def resend_confirmation(request: Request, email: str = Form("")) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    email = email.strip()
    if EMAIL_RE.match(email) and svc.email_limiter.hit(_client_key(request)):
        assert svc.auth is not None
        # Neutral response either way - do not reveal whether the account exists.
        with contextlib.suppress(AuthError):
            svc.auth.resend_confirmation(email, f"{svc.settings.site_url}/auth/callback")
    return _render(request, "auth/check_email.html", {"user": None, "email": email, "kind": "signup"})


@router.get("/forgot-password")
def forgot_page(request: Request) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    return _render(request, "auth/forgot.html", {"user": None, "email": ""})


@router.post("/forgot-password", dependencies=[Depends(verify_csrf)])
def forgot(request: Request, email: str = Form("")) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    email = email.strip()
    if not EMAIL_RE.match(email):
        return _render(
            request,
            "auth/forgot.html",
            {"user": None, "email": email, "error": "Enter a valid email address."},
            400,
        )
    if not svc.email_limiter.hit(_client_key(request)):
        return _render(
            request,
            "auth/forgot.html",
            {"user": None, "email": email, "error": "Too many requests. Please wait and try again."},
            429,
        )
    assert svc.auth is not None
    try:
        svc.auth.recover(email, f"{svc.settings.site_url}/auth/callback")
    except AuthError as exc:
        if exc.status == 429:
            return _render(
                request, "auth/forgot.html", {"user": None, "email": email, "error": str(exc)}, 429
            )
    return RedirectResponse("/login?msg=reset_sent", status_code=303)


@router.get("/auth/confirm")
def confirm(request: Request, token_hash: str = "", type: str = "signup") -> Response:
    """Server-side token-hash flow (recommended email template, see docs/SUPABASE_SETUP.md)."""
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    assert svc.auth is not None
    if not token_hash or len(token_hash) > 512:
        return RedirectResponse("/login?msg=link_invalid", status_code=303)
    try:
        session = svc.auth.verify_token_hash(token_hash, type)
    except AuthError:
        return RedirectResponse("/login?msg=link_invalid", status_code=303)
    return _finish_link_login(svc, session, recovery=type == "recovery")


def _finish_link_login(svc: Services, session, *, recovery: bool) -> Response:
    if recovery:
        response = RedirectResponse("/reset-password?msg=recovery_ready", status_code=303)
        _set_session_cookie(response, svc, svc.sessions.create(session, purpose="recovery"))
    else:
        response = RedirectResponse("/dashboard?msg=confirmed", status_code=303)
        _set_session_cookie(response, svc, svc.sessions.create(session))
    return response


@router.get("/auth/callback")
def callback_page(request: Request) -> Response:
    """Default Supabase email links return tokens in the URL fragment, which only the browser can
    read. A small same-origin script posts them to /auth/session, where they are validated."""
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    return _render(request, "auth/callback.html", {"user": None})


class FragmentTokens(BaseModel):
    access_token: str = Field(min_length=10, max_length=4096)
    refresh_token: str = Field(min_length=1, max_length=512)
    expires_at: int | None = None
    type: str | None = Field(default=None, max_length=32)


@router.post("/auth/session", dependencies=[Depends(verify_csrf)])
def session_from_fragment(body: FragmentTokens, request: Request) -> Response:
    svc = services(request)
    if not svc.settings.supabase_enabled or svc.auth is None:
        return JSONResponse({"detail": "Accounts are not enabled."}, status_code=404)
    try:
        session = svc.auth.session_from_tokens(body.access_token, body.refresh_token, body.expires_at)
    except AuthError:
        return JSONResponse({"detail": "This link is invalid or has expired."}, status_code=400)
    redirect = _finish_link_login(svc, session, recovery=body.type == "recovery")
    response = JSONResponse({"redirect": redirect.headers["location"]})
    response.headers.append("set-cookie", redirect.headers["set-cookie"])
    return response


@router.get("/reset-password")
def reset_page(request: Request) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    session = svc.sessions.get(request.cookies.get(SESSION_COOKIE))
    if session is None:
        return RedirectResponse("/forgot-password", status_code=303)
    return _render(request, "auth/reset.html", {"user": None, "email": session.email})


@router.post("/reset-password", dependencies=[Depends(verify_csrf)])
def reset(request: Request, password: str = Form(""), confirm_password: str = Form("")) -> Response:
    svc = services(request)
    if (redirect := _local_mode_redirect(svc)) is not None:
        return redirect
    raw = request.cookies.get(SESSION_COOKIE)
    session = svc.sessions.get(raw)
    if session is None:
        return RedirectResponse("/login?msg=link_invalid", status_code=303)
    session = svc.fresh_session(session)
    if session is None:
        return RedirectResponse("/login?msg=expired", status_code=303)
    problem = _password_problem(password, confirm_password)
    if problem:
        return _render(
            request, "auth/reset.html", {"user": None, "email": session.email, "error": problem}, 400
        )
    assert svc.auth is not None
    try:
        svc.auth.update_password(session.access_token, password)
    except AuthError as exc:
        return _render(
            request, "auth/reset.html", {"user": None, "email": session.email, "error": str(exc)}, 400
        )
    # Invalidate every session for this user (including the recovery session) and sign in again.
    with contextlib.suppress(AuthError):
        svc.auth.sign_out(session.access_token, scope="global")
    svc.sessions.delete_user_sessions(session.user_id)
    response = RedirectResponse("/login?msg=password_updated", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request) -> Response:
    svc = services(request)
    if not svc.settings.supabase_enabled:
        return RedirectResponse("/", status_code=303)
    raw = request.cookies.get(SESSION_COOKIE)
    session = svc.sessions.get(raw)
    if session is not None and svc.auth is not None:
        with contextlib.suppress(AuthError):
            svc.auth.sign_out(session.access_token, scope="local")
    svc.sessions.delete(raw)
    response = RedirectResponse("/login?msg=signed_out", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.post("/settings/password", dependencies=[Depends(verify_csrf)])
def change_password(
    request: Request,
    password: str = Form(""),
    confirm_password: str = Form(""),
    user: CurrentUser = Depends(require_user),
) -> Response:
    svc = services(request)
    if user.is_local or svc.auth is None:
        return RedirectResponse("/settings", status_code=303)
    problem = _password_problem(password, confirm_password)
    if problem is None:
        try:
            svc.auth.update_password(user.token_supplier(), password)
            return RedirectResponse("/settings?msg=password_updated", status_code=303)
        except AuthError as exc:
            problem = str(exc)
    from white.api.routes_web import render_settings

    return render_settings(request, user, error=problem, status_code=400)


@router.post("/settings/sign-out-everywhere", dependencies=[Depends(verify_csrf)])
def sign_out_everywhere(request: Request, user: CurrentUser = Depends(require_user)) -> Response:
    svc = services(request)
    if user.is_local or svc.auth is None:
        return RedirectResponse("/settings", status_code=303)
    with contextlib.suppress(AuthError):
        svc.auth.sign_out(user.token_supplier(), scope="global")
    svc.sessions.delete_user_sessions(user.id)
    response = RedirectResponse("/login?msg=signed_out_everywhere", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response

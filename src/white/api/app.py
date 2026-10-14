"""FastAPI application factory for the WHITE web GUI and JSON API."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from white import __version__
from white.api.deps import LoginRequired, Services
from white.api.jobs import JobManager
from white.api.security import SecurityMiddleware, csrf_token_for
from white.auth.admin import AdminAuth
from white.auth.domains import DomainStore
from white.auth.passwords import hash_password
from white.auth.sessions import CookieSessionStore, SessionStore
from white.auth.supabase_auth import SupabaseAuthClient
from white.config import Settings, get_settings
from white.database.base import RepositoryError
from white.database.sqlite import SQLiteDatabase, SQLiteScanRepository
from white.scanner.models import CATEGORY_LABELS, STATUS_LABELS

log = logging.getLogger("white")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

MESSAGES = {
    "signed_out": ("success", "You have been signed out."),
    "expired": ("info", "Your session has expired. Please sign in again."),
    "login": ("info", "Please sign in to continue."),
    "password_updated": ("success", "Your password has been updated."),
    "reset_sent": ("success", "If an account exists for that email, a password reset link has been sent."),
    "confirmed": ("success", "Your email address is confirmed. Welcome to WHITE."),
    "link_invalid": ("error", "This link is invalid or has expired. Please request a new one."),
    "scan_deleted": ("success", "The scan was deleted."),
    "scan_cancelled": ("info", "Cancellation requested. The scan stops after the current check."),
    "domain_added": ("success", "Domain added. Follow the steps below to verify ownership."),
    "domain_verified": ("success", "Domain ownership verified. You can now scan this domain."),
    "domain_not_verified": (
        "error",
        "Verification failed: the DNS record or file was not found yet. "
        "DNS changes can take a while to appear; try again later.",
    ),
    "domain_deleted": ("success", "Domain removed."),
    "signed_out_everywhere": ("success", "You have been signed out on all devices."),
    "recovery_ready": ("info", "Choose a new password for your account."),
}


def build_services(settings: Settings) -> Services:
    db = SQLiteDatabase(settings.sqlite_path)
    local_repo = SQLiteScanRepository(db)
    interrupted = local_repo.mark_interrupted()
    if interrupted:
        log.warning("%d unfinished local scan(s) marked as interrupted", interrupted)
    auth = (
        SupabaseAuthClient(settings.supabase_url, settings.supabase_publishable_key)
        if settings.supabase_enabled
        else None
    )  # type: ignore[arg-type]
    admin = None
    if settings.admin_enabled:
        digest = settings.admin_password_hash or hash_password(settings.admin_password)
        admin = AdminAuth(
            settings.admin_user,
            digest,
            settings.effective_secret_key(),
            default_password=settings.admin_uses_default_password,
        )
        if settings.admin_uses_default_password and not settings.is_serverless:
            log.warning(
                "Admin console enabled with the default password. Set WHITE_ADMIN_PASSWORD_HASH "
                "to a strong value for anything beyond local use."
            )
    services = Services(
        settings=settings,
        db=db,
        local_repo=local_repo,
        sessions=(
            CookieSessionStore(settings.effective_secret_key())
            if settings.is_serverless
            else SessionStore(db, settings.effective_secret_key())
        ),
        domains=DomainStore(db),
        jobs=JobManager(settings.max_concurrent_scans, settings.scans_per_user_per_hour),
        auth=auth,
        admin=admin,
    )
    services.sessions.purge_expired()
    return services


def _allowed_hosts(settings: Settings) -> list[str]:
    hosts = {"127.0.0.1", "localhost", "[::1]", "testserver"}
    site_host = urlsplit(settings.site_url).hostname
    if site_host:
        hosts.add(site_host)
    hosts.update(settings.deployment_hosts)
    return sorted(hosts)


def _misconfigured_app(problems: list[str]) -> FastAPI:
    """A hosted deployment with unsafe settings serves only an explanation, never the scanner."""
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="WHITE (configuration required)", docs_url=None, redoc_url=None, openapi_url=None)
    items = "".join(f"<li>{p}</li>" for p in problems)
    page = (
        "<!doctype html><meta charset='utf-8'><title>WHITE - configuration required</title>"
        "<body style='font-family:system-ui;max-width:640px;margin:64px auto;padding:0 16px;line-height:1.6'>"
        "<h1>WHITE needs configuration</h1><p>This deployment is not started because:</p>"
        f"<ul>{items}</ul><p>Set these environment variables in your hosting provider's project settings "
        "and redeploy. See docs/DEPLOY_VERCEL.md.</p></body>"
    )

    @app.get("/api/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "misconfigured"}, status_code=503)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def blocked(path: str) -> HTMLResponse:
        return HTMLResponse(page, status_code=503)

    log.error("WHITE not started: %s", "; ".join(problems))
    return app


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or (services.settings if services else get_settings())
    problems = settings.configuration_problems()
    if problems:
        return _misconfigured_app(problems)
    if not settings.secret_key:
        log.warning("WHITE_SECRET_KEY is not set; a temporary key is used and sessions reset on restart.")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.services.jobs.shutdown()

    app = FastAPI(
        title="WHITE",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.services = services or build_services(settings)
    app.add_middleware(SecurityMiddleware, secure_cookies=settings.secure_cookies)
    # Rejecting unknown Host headers blocks DNS-rebinding attacks against a local server.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts(settings))
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    templates = Jinja2Templates(directory=WEB_DIR / "templates")
    env = templates.env
    env.globals.update(
        app_version=__version__,
        auth_mode=settings.auth_mode,
        domain_verification=settings.domain_verification_required,
        admin_enabled=settings.admin_enabled,
        status_labels=STATUS_LABELS,
        category_labels={k.value: v for k, v in CATEGORY_LABELS.items()},
    )
    env.globals["csrf_token"] = lambda request: csrf_token_for(
        settings.effective_secret_key(), request.state.csrf_cookie
    )
    env.globals["flash"] = lambda request: MESSAGES.get(request.query_params.get("msg", ""))
    env.filters["dt"] = lambda d: d.strftime("%d %b %Y, %H:%M UTC") if d else "-"
    app.state.templates = templates

    def wants_json(request: Request) -> bool:
        return request.url.path.startswith("/api/")

    def safe_user(request: Request):
        """Resolve the signed-in user for the error page's nav, tolerating any failure."""
        from white.api.deps import optional_user

        try:
            return optional_user(request)
        except Exception:  # noqa: BLE001 - never let the error page itself error
            return None

    def error_page(request: Request, status: int, message: str | None):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"status": status, "message": message, "user": safe_user(request)},
            status_code=status,
        )

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        if wants_json(request):
            return JSONResponse({"detail": "Authentication required."}, status_code=401)
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"/login?msg={exc.reason}&next={quote(target)}", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        # Catches both route-raised HTTPExceptions and unmatched-URL 404s from routing.
        if wants_json(request):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        return error_page(request, exc.status_code, exc.detail)

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        # Last resort for an unexpected error: a friendly page, never a stack trace or details.
        log.exception("unhandled error at %s", request.url.path)
        if wants_json(request):
            return JSONResponse({"detail": "An unexpected error occurred."}, status_code=500)
        return error_page(request, 500, None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        if wants_json(request):
            return JSONResponse(
                {
                    "detail": "Invalid request.",
                    "errors": [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()],
                },
                status_code=422,
            )
        return error_page(request, 422, "The submitted information was not valid.")

    @app.exception_handler(RepositoryError)
    async def repository_error(request: Request, exc: RepositoryError):
        from white.database.supabase import SessionExpiredError

        if isinstance(exc, SessionExpiredError) and not wants_json(request):
            return RedirectResponse("/login?msg=expired", status_code=303)
        if wants_json(request):
            return JSONResponse({"detail": str(exc)}, status_code=503)
        return error_page(request, 503, str(exc))

    from white.api import routes_admin, routes_api, routes_auth, routes_web

    app.include_router(routes_api.router)
    app.include_router(routes_auth.router)
    if settings.admin_enabled:
        app.include_router(routes_admin.router)
    app.include_router(routes_web.router)
    return app

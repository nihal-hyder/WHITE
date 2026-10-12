"""FastAPI application factory for the WHITE web GUI and JSON API."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from white import __version__
from white.api.deps import LoginRequired, Services
from white.api.jobs import JobManager
from white.api.security import SecurityMiddleware, csrf_token_for
from white.auth.domains import DomainStore
from white.auth.sessions import SessionStore
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
    services = Services(
        settings=settings,
        db=db,
        local_repo=local_repo,
        sessions=SessionStore(db, settings.effective_secret_key()),
        domains=DomainStore(db),
        jobs=JobManager(settings.max_concurrent_scans, settings.scans_per_user_per_hour),
        auth=auth,
    )
    services.sessions.purge_expired()
    return services


def _allowed_hosts(settings: Settings) -> list[str]:
    hosts = {"127.0.0.1", "localhost", "[::1]", "testserver"}
    site_host = urlsplit(settings.site_url).hostname
    if site_host:
        hosts.add(site_host)
    return sorted(hosts)


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or (services.settings if services else get_settings())
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
        docs_url="/api/docs",
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

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        if wants_json(request):
            return JSONResponse({"detail": "Authentication required."}, status_code=401)
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"/login?msg={exc.reason}&next={quote(target)}", status_code=303)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if wants_json(request):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        return templates.TemplateResponse(
            request,
            "error.html",
            {"status": exc.status_code, "message": exc.detail, "user": None},
            status_code=exc.status_code,
        )

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
        return templates.TemplateResponse(
            request,
            "error.html",
            {"status": 422, "message": "The submitted information was not valid.", "user": None},
            status_code=422,
        )

    @app.exception_handler(RepositoryError)
    async def repository_error(request: Request, exc: RepositoryError):
        from white.database.supabase import SessionExpiredError

        if isinstance(exc, SessionExpiredError) and not wants_json(request):
            return RedirectResponse("/login?msg=expired", status_code=303)
        if wants_json(request):
            return JSONResponse({"detail": str(exc)}, status_code=503)
        return templates.TemplateResponse(
            request, "error.html", {"status": 503, "message": str(exc), "user": None}, status_code=503
        )

    from white.api import routes_api, routes_auth, routes_web

    app.include_router(routes_api.router)
    app.include_router(routes_auth.router)
    app.include_router(routes_web.router)
    return app

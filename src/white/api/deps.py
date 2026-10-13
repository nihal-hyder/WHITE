"""Shared services and request-scoped authentication/authorization helpers."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request

from white.api.jobs import JobManager
from white.api.security import SESSION_COOKIE, RateLimiter, csrf_valid, same_origin
from white.auth.domains import DomainStore
from white.auth.domains_supabase import SupabaseDomainStore
from white.auth.sessions import CookieSessionStore, SessionData, SessionStore
from white.auth.supabase_auth import AuthError, AuthSession, SupabaseAuthClient
from white.config import Settings
from white.database.base import ScanRepository
from white.database.sqlite import SQLiteDatabase, SQLiteScanRepository
from white.database.supabase import SupabaseScanRepository

log = logging.getLogger("white.auth")
LOCAL_USER_ID = "local"
REFRESH_MARGIN = 120


class LoginRequired(Exception):
    def __init__(self, reason: str = "login") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Services:
    settings: Settings
    db: SQLiteDatabase
    local_repo: SQLiteScanRepository
    sessions: SessionStore | CookieSessionStore
    domains: DomainStore
    jobs: JobManager
    auth: SupabaseAuthClient | None
    login_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(10, 900))
    email_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(5, 900))
    supabase_transport: Any = None  # injectable for tests
    _refresh_lock: threading.Lock = field(default_factory=threading.Lock)
    _bearer_cache: dict[str, tuple[float, str, str]] = field(default_factory=dict)
    _validated: dict[str, float] = field(default_factory=dict)

    @property
    def secret(self) -> str:
        return self.settings.effective_secret_key()

    def fresh_session(self, session: SessionData) -> SessionData | None:
        """Return the session with a valid access token, refreshing it when close to expiry."""
        if session.access_expires_at - time.time() > REFRESH_MARGIN:
            return session
        assert self.auth is not None
        with self._refresh_lock:
            current = self.sessions.get_by_hash(session.id_hash)
            if current is None:
                return None
            if current.access_expires_at - time.time() > REFRESH_MARGIN:
                return current
            try:
                refreshed = self.auth.refresh(current.refresh_token)
            except AuthError as exc:
                log.info("session refresh failed: %s", exc.code)
                self.sessions.delete_hash(current.id_hash)
                return None
            self.sessions.update_tokens(current.id_hash, refreshed)
            return self.sessions.get_by_hash(current.id_hash)

    def token_supplier(self, id_hash: str):
        def supply() -> str:
            current = self.sessions.get_by_hash(id_hash)
            fresh = self.fresh_session(current) if current else None
            if fresh is None:
                raise LoginRequired("expired")
            return fresh.access_token

        return supply

    def repo_for(self, user: CurrentUser) -> ScanRepository:
        if user.mode == "local":
            return self.local_repo
        assert self.settings.supabase_url and self.settings.supabase_publishable_key
        return SupabaseScanRepository(
            self.settings.supabase_url,
            self.settings.supabase_publishable_key,
            user.token_supplier,
            transport=self.supabase_transport,
            inline_columns=self.settings.execution_mode == "inline",
        )

    def domains_for(self, user: CurrentUser) -> DomainStore | SupabaseDomainStore:
        """Serverless deployments keep verification in Supabase (signed); others in local SQLite."""
        if self.settings.is_serverless and user.mode == "supabase":
            assert self.settings.supabase_url and self.settings.supabase_publishable_key
            return SupabaseDomainStore(
                self.settings.supabase_url,
                self.settings.supabase_publishable_key,
                user.token_supplier,
                self.secret,
                transport=self.supabase_transport,
            )
        return self.domains

    def session_still_valid(self, session: SessionData) -> bool:
        """Stateless sessions cannot be deleted server-side, so confirm with Supabase that the
        session behind the access token still exists (sign-out revokes it). Cached briefly."""
        if not getattr(self.sessions, "stateless", False):
            return True
        assert self.auth is not None
        key = hashlib.sha256(session.access_token.encode()).hexdigest()
        now = time.time()
        if self._validated.get(key, 0) > now:
            return True
        try:
            user = self.auth.get_user(session.access_token)
        except AuthError as exc:
            if exc.status in {401, 403, 404}:
                return False
            raise
        if user.get("id") != session.user_id:
            return False
        if len(self._validated) > 5000:
            self._validated.clear()
        self._validated[key] = now + 30
        return True


@dataclass
class CurrentUser:
    id: str
    email: str
    mode: str  # 'local' | 'supabase'
    token_supplier: Any = None
    session: SessionData | None = None

    @property
    def is_local(self) -> bool:
        return self.mode == "local"


def services(request: Request) -> Services:
    return request.app.state.services


def _bearer_user(svc: Services, token: str) -> CurrentUser | None:
    assert svc.auth is not None
    key = hashlib.sha256(token.encode()).hexdigest()
    cached = svc._bearer_cache.get(key)
    if cached and cached[0] > time.time():
        return CurrentUser(id=cached[1], email=cached[2], mode="supabase", token_supplier=lambda: token)
    try:
        user = svc.auth.get_user(token)
    except AuthError:
        return None
    if not user.get("id"):
        return None
    if len(svc._bearer_cache) > 1000:
        svc._bearer_cache.clear()
    svc._bearer_cache[key] = (time.time() + 60, user["id"], user.get("email") or "")
    return CurrentUser(
        id=user["id"], email=user.get("email") or "", mode="supabase", token_supplier=lambda: token
    )


def optional_user(request: Request) -> CurrentUser | None:
    svc = services(request)
    if not svc.settings.supabase_enabled:
        return CurrentUser(id=LOCAL_USER_ID, email="Local user", mode="local")
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        user = _bearer_user(svc, auth_header[7:].strip())
        if user:
            request.state.bearer = True
        return user
    session = svc.sessions.get(request.cookies.get(SESSION_COOKIE))
    if session is None or session.purpose != "login":
        return None
    fresh = svc.fresh_session(session)
    if fresh is None or not svc.session_still_valid(fresh):
        request.state.session_expired = True
        if fresh is not None:
            svc.sessions.delete_hash(fresh.id_hash)
        return None
    return CurrentUser(
        id=fresh.user_id,
        email=fresh.email,
        mode="supabase",
        token_supplier=svc.token_supplier(fresh.id_hash),
        session=fresh,
    )


def client_ip(request: Request) -> str:
    """The visitor's IP. Behind a trusted proxy (e.g. Vercel) use its forwarded headers."""
    svc = services(request)
    if svc.settings.proxy_headers_trusted:
        real = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0]
        if real.strip():
            return real.strip()[:64]
    return request.client.host if request.client else "unknown"


def require_user(request: Request) -> CurrentUser:
    user = optional_user(request)
    if user is None:
        raise LoginRequired("expired" if getattr(request.state, "session_expired", False) else "login")
    return user


def require_api_user(request: Request) -> CurrentUser:
    user = optional_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


async def verify_csrf(request: Request) -> None:
    """For state-changing requests authenticated by cookie (bearer tokens are exempt)."""
    svc = services(request)
    if svc.settings.supabase_enabled and request.headers.get("authorization", "").lower().startswith(
        "bearer "
    ):
        # Bearer tokens are not sent automatically by browsers, so CSRF does not apply. The token
        # itself is validated by the user dependency.
        return
    if not same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-site request rejected.")
    submitted = request.headers.get("x-csrf-token")
    if submitted is None:
        content_type = request.headers.get("content-type", "")
        if "form" in content_type:
            form = await request.form()
            value = form.get("csrf_token")
            submitted = value if isinstance(value, str) else None
    if not csrf_valid(svc.secret, request.cookies.get("white_csrf"), submitted):
        raise HTTPException(status_code=403, detail="Your form expired. Reload the page and try again.")


def new_login_session(svc: Services, auth: AuthSession, purpose: str = "login") -> str:
    return svc.sessions.create(auth, purpose=purpose)

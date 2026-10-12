"""Web security helpers: CSRF protection, security headers, simple rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CSRF_COOKIE = "white_csrf"
SESSION_COOKIE = "white_session"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


def csrf_token_for(secret: str, cookie_value: str) -> str:
    return hmac.new(secret.encode(), f"csrf:{cookie_value}".encode(), hashlib.sha256).hexdigest()


def csrf_valid(secret: str, cookie_value: str | None, submitted: str | None) -> bool:
    if not cookie_value or not submitted:
        return False
    return hmac.compare_digest(csrf_token_for(secret, cookie_value), submitted)


def same_origin(request: Request) -> bool:
    """Reject cross-site state-changing requests when the browser tells us the origin."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin or origin == "null":
        return origin is None
    host = request.headers.get("host", "")
    return urlsplit(origin).netloc.lower() == host.lower()


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, secure_cookies: bool) -> None:
        super().__init__(app)
        self.secure_cookies = secure_cookies

    async def dispatch(self, request: Request, call_next) -> Response:
        cookie = request.cookies.get(CSRF_COOKIE)
        new_cookie = None
        if not cookie or len(cookie) > 100:
            new_cookie = secrets.token_urlsafe(24)
            cookie = new_cookie
        request.state.csrf_cookie = cookie
        response = await call_next(request)
        if new_cookie:
            response.set_cookie(
                CSRF_COOKIE, new_cookie, httponly=True, samesite="lax", secure=self.secure_cookies, path="/"
            )
        headers = response.headers
        headers.setdefault("Content-Security-Policy", CSP)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "same-origin")
        headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if self.secure_cookies:
            headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if not request.url.path.startswith("/static/"):
            headers.setdefault("Cache-Control", "no-store")
        return response


class RateLimiter:
    """Sliding-window limiter keyed by arbitrary strings (in memory, per process)."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record an attempt. Returns False when the limit is exceeded."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

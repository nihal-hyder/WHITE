"""Shared fixtures: a mock website, a fake Supabase backend and app factories.

No test contacts a real external website or the real Supabase project.
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from white.config import Settings
from white.scanner.engine import Scanner
from white.scanner.models import ScanConfig

SECURE_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
    "server": "nginx",
}
GOOD_HTML = "<html><head><title>Shop</title><script src='/app.js'></script></head><body>Hello</body></html>"


class MockSite:
    """Routes keyed by full URL -> (status, headers, body). Unknown URLs return 404."""

    def __init__(self, routes: dict[str, tuple[int, dict, bytes | str]] | None = None) -> None:
        self.routes = routes or {}
        self.requests: list[httpx.Request] = []
        self.errors: dict[str, Exception] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url in self.errors:
            raise self.errors[url]
        key = url
        if key not in self.routes:
            key = url.split("?")[0]
        if key not in self.routes:
            return httpx.Response(404, headers={"content-type": "text/html"}, text="<h1>Not found</h1>")
        status, headers, body = self.routes[key]
        if callable(body):
            body = body(request)
        content = body.encode() if isinstance(body, str) else body
        return httpx.Response(status, headers=headers, content=content)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def good_site(host: str = "shop.example.com") -> MockSite:
    return MockSite(
        {
            f"https://{host}/": (200, SECURE_HEADERS, GOOD_HTML),
            f"http://{host}/": (301, {"location": f"https://{host}/"}, b""),
        }
    )


@pytest.fixture
def site_factory() -> Callable[..., MockSite]:
    return good_site


def run_scan(site: MockSite, url: str = "https://shop.example.com/", **config) -> object:
    cfg = ScanConfig(min_request_interval=0, **config)
    return Scanner(cfg, transport=site.transport).run(url)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    for name in (
        "SUPABASE_URL",
        "SUPABASE_PUBLISHABLE_KEY",
        "SUPABASE_ANON_KEY",
        "WHITE_SECRET_KEY",
        "WHITE_DATA_DIR",
        "WHITE_ALLOW_PRIVATE_TARGETS",
        "WHITE_REQUIRE_DOMAIN_VERIFICATION",
        "WHITE_SITE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)  # no project .env is picked up


# ----------------------------------------------------------------------------- fake Supabase
FAKE_URL = "https://fake-project.supabase.co"
FAKE_KEY = "sb_publishable_test_key"


class FakeSupabase:
    """Minimal Supabase Auth + PostgREST emulation.

    Row ownership is enforced from the bearer token (like RLS), deliberately ignoring the
    user_id filter sent by the client, so tests prove isolation does not depend on it.
    """

    def __init__(self, confirm_email: bool = False) -> None:
        self.confirm_email = confirm_email
        self.users: dict[str, dict] = {}
        self.access: dict[str, tuple[str, float]] = {}
        self.refresh: dict[str, str] = {}
        self.token_hashes: dict[str, tuple[str, str]] = {}
        self.tables: dict[str, list[dict]] = {"scans": [], "findings": [], "verified_domains": []}
        self.calls: list[str] = []
        self.access_ttl = 3600

    # helpers
    def add_user(self, email: str, password: str, confirmed: bool = True) -> str:
        uid = str(uuid.uuid4())
        self.users[email] = {"id": uid, "email": email, "password": password, "confirmed": confirmed}
        return uid

    def _session(self, user: dict) -> dict:
        at, rt = "at-" + secrets.token_hex(8), "rt-" + secrets.token_hex(8)
        self.access[at] = (user["id"], time.time() + self.access_ttl)
        self.refresh[rt] = user["id"]
        return {
            "access_token": at,
            "refresh_token": rt,
            "expires_in": self.access_ttl,
            "expires_at": int(time.time() + self.access_ttl),
            "token_type": "bearer",
            "user": {"id": user["id"], "email": user["email"]},
        }

    def _user_by_id(self, uid: str) -> dict | None:
        return next((u for u in self.users.values() if u["id"] == uid), None)

    def _auth_uid(self, request: httpx.Request) -> str | None:
        token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        entry = self.access.get(token)
        if entry is None or entry[1] < time.time():
            return None
        return entry[0]

    @staticmethod
    def _error(status: int, code: str, msg: str = "error") -> httpx.Response:
        return httpx.Response(status, json={"code": status, "error_code": code, "msg": msg})

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers.get("apikey") == FAKE_KEY
        parts = urlsplit(str(request.url))
        path = parts.path
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        body = json.loads(request.content) if request.content else None
        self.calls.append(f"{request.method} {path}")
        if path.startswith("/auth/v1/"):
            return self._auth(request, path.removeprefix("/auth/v1/"), query, body)
        if path.startswith("/rest/v1/"):
            return self._rest(request, path.removeprefix("/rest/v1/"), query, body)
        return httpx.Response(404)

    def _auth(self, request, path, query, body) -> httpx.Response:
        if path == "signup":
            if body["email"] in self.users:
                if self.confirm_email:  # enumeration-safe obfuscated response
                    return httpx.Response(200, json={"id": str(uuid.uuid4()), "identities": []})
                return self._error(422, "user_already_exists")
            if len(body["password"]) < 6:
                return self._error(422, "weak_password")
            self.add_user(body["email"], body["password"], confirmed=not self.confirm_email)
            user = self.users[body["email"]]
            if self.confirm_email:
                return httpx.Response(200, json={"id": user["id"], "email": user["email"]})
            return httpx.Response(200, json=self._session(user))
        if path == "token" and query.get("grant_type") == "password":
            user = self.users.get(body["email"])
            if not user or user["password"] != body["password"]:
                return httpx.Response(
                    400, json={"error": "invalid_grant", "error_description": "Invalid login credentials"}
                )
            if not user["confirmed"]:
                return self._error(400, "email_not_confirmed")
            return httpx.Response(200, json=self._session(user))
        if path == "token" and query.get("grant_type") == "refresh_token":
            uid = self.refresh.pop(body["refresh_token"], None)
            if uid is None:
                return self._error(400, "refresh_token_not_found")
            return httpx.Response(200, json=self._session(self._user_by_id(uid)))
        if path == "user" and request.method == "GET":
            uid = self._auth_uid(request)
            if uid is None:
                return self._error(401, "bad_jwt")
            user = self._user_by_id(uid)
            return httpx.Response(200, json={"id": uid, "email": user["email"]})
        if path == "user" and request.method == "PUT":
            uid = self._auth_uid(request)
            if uid is None:
                return self._error(401, "bad_jwt")
            user = self._user_by_id(uid)
            if user["password"] == body["password"]:
                return self._error(422, "same_password")
            user["password"] = body["password"]
            return httpx.Response(200, json={"id": uid})
        if path == "logout":
            uid = self._auth_uid(request)
            if uid is None:
                return self._error(401, "bad_jwt")
            token = request.headers["authorization"].removeprefix("Bearer ")
            if query.get("scope") == "global":
                self.access = {k: v for k, v in self.access.items() if v[0] != uid}
                self.refresh = {k: v for k, v in self.refresh.items() if v != uid}
            else:
                self.access.pop(token, None)
            return httpx.Response(204)
        if path in {"recover", "resend"}:
            return httpx.Response(200, json={})
        if path == "verify":
            entry = self.token_hashes.pop(body.get("token_hash"), None)
            if entry is None or entry[1] != body.get("type"):
                return self._error(403, "otp_expired")
            user = self.users[entry[0]]
            user["confirmed"] = True
            return httpx.Response(200, json=self._session(user))
        return httpx.Response(404)

    def _matches(self, row: dict, query: dict) -> bool:
        for key, raw in query.items():
            if key in {"select", "order", "limit"} or key == "user_id":
                continue  # user_id filter deliberately ignored: ownership comes from the token
            if raw.startswith("eq.") and str(row.get(key)) != raw[3:]:
                return False
            if raw == "not.is.null" and row.get(key) is None:
                return False
            if raw.startswith("not.in.(") and row.get(key) in raw[8:-1].split(","):
                return False
            if raw.startswith("in.(") and row.get(key) not in raw[4:-1].split(","):
                return False
            if raw.startswith("gte."):
                from datetime import datetime

                if row.get(key) is None or datetime.fromisoformat(str(row[key])) < datetime.fromisoformat(
                    raw[4:]
                ):
                    return False
        return True

    def _rest(self, request, table, query, body) -> httpx.Response:
        uid = self._auth_uid(request)
        if uid is None:
            return httpx.Response(401, json={"message": "JWT expired"})
        rows = self.tables[table]
        visible = [r for r in rows if r["user_id"] == uid]  # RLS
        if request.method == "POST":
            items = body if isinstance(body, list) else [body]
            for item in items:
                if item.get("user_id") != uid:
                    return httpx.Response(403, json={"message": "new row violates row-level security policy"})
                if table == "findings" and not any(
                    s["id"] == item["scan_id"] and s["user_id"] == uid for s in self.tables["scans"]
                ):
                    return httpx.Response(403, json={"message": "row-level security"})
            rows.extend(dict(i) for i in items)
            if "return=representation" in request.headers.get("prefer", ""):
                return httpx.Response(201, json=[dict(i) for i in items])
            return httpx.Response(201)
        matched = [r for r in visible if self._matches(r, query)]
        if request.method == "GET":
            matched.sort(key=lambda r: r.get("created_at", ""), reverse=True)
            if "limit" in query:
                matched = matched[: int(query["limit"])]
            return httpx.Response(200, json=matched)
        if request.method == "PATCH":
            for r in matched:
                r.update(body)
            return httpx.Response(200, json=matched)
        if request.method == "DELETE":
            for r in matched:
                rows.remove(r)
            return httpx.Response(200, json=matched)
        return httpx.Response(405)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


@pytest.fixture
def fake_supabase() -> FakeSupabase:
    return FakeSupabase()


def make_settings(tmp_path, supabase: bool = False, **extra) -> Settings:
    values = {"WHITE_DATA_DIR": str(tmp_path / "data"), "WHITE_SECRET_KEY": "test-secret-key-0123456789"}
    if supabase:
        values.update({"SUPABASE_URL": FAKE_URL, "SUPABASE_PUBLISHABLE_KEY": FAKE_KEY})
    values.update(extra)
    return Settings(_env_file=None, **values)


def make_client(tmp_path, site: MockSite | None = None, supabase: FakeSupabase | None = None, **extra):
    from fastapi.testclient import TestClient

    from white.api.app import build_services, create_app
    from white.api.jobs import JobManager
    from white.auth.supabase_auth import SupabaseAuthClient

    settings = make_settings(tmp_path, supabase=supabase is not None, **extra)
    services = build_services(settings)
    site = site or good_site()
    services.jobs = JobManager(
        3,
        100,
        scanner_factory=lambda cfg: Scanner(
            cfg.model_copy(update={"min_request_interval": 0}), transport=site.transport
        ),
    )
    if supabase is not None:
        services.auth = SupabaseAuthClient(FAKE_URL, FAKE_KEY, transport=supabase.transport)
        services.supabase_transport = supabase.transport
    app = create_app(settings, services)
    return TestClient(app, base_url="http://127.0.0.1:8000")


def csrf(client, path: str = "/scans/new") -> str:
    import re

    html = client.get(path).text
    match = re.search(r'name="csrf-token" content="([^"]+)"', html)
    assert match, "csrf token not found"
    return match.group(1)


def wait_for_scan(client, scan_id: str, timeout: float = 15.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f"/api/scans/{scan_id}/status").json()
        if status["state"] not in {"queued", "running"}:
            return status
        time.sleep(0.05)
    raise AssertionError("scan did not finish")

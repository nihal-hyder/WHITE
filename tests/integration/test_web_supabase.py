"""Supabase mode against a fake Supabase: authentication, sessions and cross-user isolation."""

from __future__ import annotations

import time

import pytest

from tests.conftest import FakeSupabase, csrf, make_client, wait_for_scan

PASSWORD = "correct-horse-battery"


@pytest.fixture
def supa():
    return FakeSupabase()


def login(client, email, password=PASSWORD):
    token = csrf(client, "/login")
    return client.post(
        "/login",
        data={"csrf_token": token, "email": email, "password": password, "next": "/dashboard"},
        follow_redirects=False,
    )


def start_scan(client):
    token = csrf(client)
    return client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    )


def test_protected_pages_require_login(tmp_path, supa):
    client = make_client(tmp_path, supabase=supa)
    for path in ["/dashboard", "/history", "/scans/new", "/settings", "/domains"]:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"].startswith("/login"), path
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/health").status_code == 200


def test_signup_without_confirmation_signs_in(tmp_path, supa):
    client = make_client(tmp_path, supabase=supa)
    token = csrf(client, "/signup")
    r = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": "a@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/dashboard")
    assert client.get("/dashboard").status_code == 200


def test_signup_validation_and_duplicates(tmp_path, supa):
    supa.add_user("taken@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    token = csrf(client, "/signup")
    short = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": "b@example.com",
            "password": "short",
            "confirm_password": "short",
        },
    )
    assert short.status_code == 400 and "at least 8" in short.text
    mismatch = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": "b@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD + "x",
        },
    )
    assert "do not match" in mismatch.text
    dup = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": "taken@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert dup.status_code == 400 and "already exists" in dup.text


def test_signup_with_email_confirmation(tmp_path):
    supa = FakeSupabase(confirm_email=True)
    client = make_client(tmp_path, supabase=supa)
    token = csrf(client, "/signup")
    r = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": "c@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert "Check your email" in r.text
    blocked = login(client, "c@example.com")
    assert "confirm your email" in blocked.text
    supa.token_hashes["hash123"] = ("c@example.com", "signup")
    confirmed = client.get("/auth/confirm?token_hash=hash123&type=signup", follow_redirects=False)
    assert confirmed.headers["location"] == "/dashboard?msg=confirmed"
    assert client.get("/dashboard").status_code == 200
    reused = client.get("/auth/confirm?token_hash=hash123&type=signup", follow_redirects=False)
    assert "link_invalid" in reused.headers["location"]


def test_login_errors_and_rate_limit(tmp_path, supa):
    supa.add_user("d@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    wrong = login(client, "d@example.com", "wrong-password")
    assert wrong.status_code == 400 and "incorrect" in wrong.text
    for _ in range(10):
        login(client, "d@example.com", "wrong-password")
    limited = login(client, "d@example.com", PASSWORD)
    assert limited.status_code == 429


def test_open_redirect_blocked(tmp_path, supa):
    supa.add_user("e@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    token = csrf(client, "/login")
    r = client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": "e@example.com",
            "password": PASSWORD,
            "next": "//evil.example/phish",
        },
        follow_redirects=False,
    )
    assert r.headers["location"] == "/dashboard"


def test_session_cookie_is_httponly_and_tokens_not_exposed(tmp_path, supa):
    supa.add_user("f@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    r = login(client, "f@example.com")
    cookie = r.headers["set-cookie"]
    assert "white_session=" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    page = client.get("/dashboard").text
    assert not any(token in page for token in supa.access)


def test_logout_invalidates_session(tmp_path, supa):
    supa.add_user("g@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    login(client, "g@example.com")
    session_cookie = client.cookies.get("white_session")
    token = csrf(client, "/dashboard")
    out = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    assert out.headers["location"] == "/login?msg=signed_out"
    client.cookies.set("white_session", session_cookie)  # replaying the old cookie must not work
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    assert supa.access == {}


def test_expired_access_token_is_refreshed(tmp_path, supa):
    supa.add_user("h@example.com", PASSWORD)
    supa.access_ttl = 30  # shorter than the refresh margin -> refresh on next request
    client = make_client(tmp_path, supabase=supa)
    login(client, "h@example.com")
    before = supa.calls.count("POST /auth/v1/token")
    assert client.get("/dashboard").status_code == 200
    assert supa.calls.count("POST /auth/v1/token") > before


def test_revoked_session_redirects_to_login(tmp_path, supa):
    supa.add_user("i@example.com", PASSWORD)
    supa.access_ttl = 30
    client = make_client(tmp_path, supabase=supa)
    login(client, "i@example.com")
    supa.refresh.clear()  # e.g. signed out everywhere from another device
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and "msg=expired" in r.headers["location"]


def test_cross_user_isolation(tmp_path, supa):
    supa.add_user("alice@example.com", PASSWORD)
    supa.add_user("bob@example.com", PASSWORD)
    alice = make_client(tmp_path, supabase=supa, WHITE_REQUIRE_DOMAIN_VERIFICATION="false")
    login(alice, "alice@example.com")
    scan_id = start_scan(alice).json()["scan_id"]
    assert wait_for_scan(alice, scan_id)["state"] == "completed"
    assert supa.tables["scans"][0]["report"] is not None

    from fastapi.testclient import TestClient

    bob = TestClient(alice.app, base_url="http://127.0.0.1:8000")
    login(bob, "bob@example.com")
    for path in [f"/scans/{scan_id}", f"/scans/{scan_id}/report.pdf", f"/scans/{scan_id}/report.json"]:
        assert bob.get(path).status_code == 404, path
    for path in [
        f"/api/scans/{scan_id}",
        f"/api/scans/{scan_id}/status",
        f"/api/scans/{scan_id}/findings",
        f"/api/scans/{scan_id}/report.json",
    ]:
        assert bob.get(path).status_code == 404, path
    assert bob.get("/api/scans").json() == []
    assert "shop.example.com" not in bob.get("/history").text
    token = csrf(bob)
    assert bob.post(f"/scans/{scan_id}/delete", data={"csrf_token": token}).status_code == 404
    assert bob.post(f"/api/scans/{scan_id}/cancel", headers={"X-CSRF-Token": token}).status_code == 404
    assert len(supa.tables["scans"]) == 1
    # Alice still sees her scan.
    assert alice.get(f"/api/scans/{scan_id}").status_code == 200
    assert len(alice.get("/api/scans").json()) == 1


def test_bearer_token_api_access(tmp_path, supa):
    supa.add_user("j@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa, WHITE_REQUIRE_DOMAIN_VERIFICATION="false")
    import httpx

    from tests.conftest import FAKE_KEY, FAKE_URL

    with httpx.Client(transport=supa.transport) as http:
        session = http.post(
            f"{FAKE_URL}/auth/v1/token?grant_type=password",
            headers={"apikey": FAKE_KEY},
            json={"email": "j@example.com", "password": PASSWORD},
        ).json()
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    r = client.post(
        "/api/scans", json={"url": "https://shop.example.com", "authorized": True}, headers=headers
    )
    assert r.status_code == 202
    assert client.get("/api/scans", headers=headers).status_code == 200
    assert client.get("/api/scans", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_password_reset_via_token_hash(tmp_path, supa):
    supa.add_user("k@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    token = csrf(client, "/forgot-password")
    r = client.post(
        "/forgot-password", data={"csrf_token": token, "email": "k@example.com"}, follow_redirects=False
    )
    assert r.headers["location"] == "/login?msg=reset_sent"
    supa.token_hashes["recov"] = ("k@example.com", "recovery")
    r = client.get("/auth/confirm?token_hash=recov&type=recovery", follow_redirects=False)
    assert r.headers["location"].startswith("/reset-password")
    # A recovery session is not a full login.
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    token = csrf(client, "/reset-password")
    new = "a-brand-new-password"
    r = client.post(
        "/reset-password",
        data={"csrf_token": token, "password": new, "confirm_password": new},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/login?msg=password_updated"
    assert supa.users["k@example.com"]["password"] == new
    assert login(client, "k@example.com", new).status_code == 303


def test_fragment_callback_session(tmp_path, supa):
    supa.add_user("l@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    session = supa._session(supa.users["l@example.com"])
    assert client.get("/auth/callback").status_code == 200
    token = csrf(client, "/auth/callback")
    r = client.post(
        "/auth/session",
        json={
            "access_token": session["access_token"],
            "refresh_token": session["refresh_token"],
            "expires_at": int(time.time()) + 3600,
            "type": "signup",
        },
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200 and r.json()["redirect"] == "/dashboard?msg=confirmed"
    assert client.get("/dashboard").status_code == 200
    bad = client.post(
        "/auth/session",
        json={"access_token": "at-forged-token", "refresh_token": "x"},
        headers={"X-CSRF-Token": token},
    )
    assert bad.status_code == 400


def test_change_password_and_sign_out_everywhere(tmp_path, supa):
    supa.add_user("m@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    login(client, "m@example.com")
    token = csrf(client, "/settings")
    r = client.post(
        "/settings/password", data={"csrf_token": token, "password": "x", "confirm_password": "x"}
    )
    assert r.status_code == 400 and "at least 8" in r.text
    new = "another-good-password"
    r = client.post(
        "/settings/password",
        data={"csrf_token": token, "password": new, "confirm_password": new},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/settings?msg=password_updated"
    r = client.post("/settings/sign-out-everywhere", data={"csrf_token": token}, follow_redirects=False)
    assert "signed_out_everywhere" in r.headers["location"]
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_domain_verification_default_on_in_supabase_mode(tmp_path, supa):
    supa.add_user("n@example.com", PASSWORD)
    client = make_client(tmp_path, supabase=supa)
    login(client, "n@example.com")
    r = start_scan(client)
    assert r.status_code == 403 and r.json()["code"] == "domain_unverified"


def test_local_targets_skip_domain_verification(tmp_path, supa):
    """In local accounts mode with private scanning enabled, your own machine needs no domain
    verification; public hosts still do."""
    supa.add_user("local@example.com", PASSWORD)
    client = make_client(
        tmp_path, supabase=supa, WHITE_ALLOW_PRIVATE_TARGETS="true"
    )  # domain verification stays on by default in accounts mode
    login(client, "local@example.com")
    token = csrf(client)
    # loopback target: allowed straight through
    local = client.post(
        "/api/scans",
        json={"url": "http://127.0.0.1:8444/", "authorized": True},
        headers={"X-CSRF-Token": token},
    )
    assert local.status_code == 202, local.text
    wait_for_scan(client, local.json()["scan_id"])
    # a public host is still gated on verification
    public = client.post(
        "/api/scans",
        json={"url": "https://not-mine.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    )
    assert public.status_code == 403 and public.json()["code"] == "domain_unverified"

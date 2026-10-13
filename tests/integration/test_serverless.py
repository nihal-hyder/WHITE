"""Serverless (Vercel) mode: cookie sessions, request-scoped scans, signed domain verification."""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import FakeSupabase, csrf, make_client

PASSWORD = "correct-horse-battery"
SECRET = "a-very-long-random-test-secret-0123456789abcdef"


def serverless_client(tmp_path, supa, **extra):
    return make_client(tmp_path, supabase=supa, WHITE_SERVERLESS="true", WHITE_SECRET_KEY=SECRET, **extra)


def login(client, email, password=PASSWORD, ip="203.0.113.10"):
    token = csrf(client, "/login")
    return client.post(
        "/login",
        data={"csrf_token": token, "email": email, "password": password, "next": "/dashboard"},
        headers={"x-real-ip": ip},
        follow_redirects=False,
    )


def verify_domain(client, supa, email, hostname="shop.example.com"):
    """Add a domain through the UI, then mark it verified the way the server does (signed)."""
    token = csrf(client, "/domains")
    assert (
        client.post(
            "/domains", data={"csrf_token": token, "hostname": hostname}, follow_redirects=False
        ).status_code
        == 303
    )
    from tests.conftest import FAKE_KEY, FAKE_URL
    from white.auth.domains_supabase import SupabaseDomainStore

    uid = supa.users[email]["id"]
    session = supa._session(supa.users[email])
    store = SupabaseDomainStore(
        FAKE_URL, FAKE_KEY, lambda: session["access_token"], SECRET, transport=supa.transport
    )
    record = store.get_by_host(uid, hostname)
    store.mark_verified(uid, record.id, "file")


@pytest.fixture
def supa():
    s = FakeSupabase()
    s.add_user("ceo@example.com", PASSWORD)
    s.add_user("other@example.com", PASSWORD)
    return s


def test_hosted_deployment_refuses_to_run_without_accounts(tmp_path):
    client = make_client(tmp_path, WHITE_SERVERLESS="true", WHITE_SECRET_KEY=SECRET)
    assert client.get("/").status_code == 503
    assert "WHITE needs configuration" in client.get("/dashboard").text
    assert client.get("/api/health").json() == {"status": "misconfigured"}
    weak = make_client(tmp_path, supabase=FakeSupabase(), WHITE_SERVERLESS="true", WHITE_SECRET_KEY="short")
    assert weak.get("/").status_code == 503


def test_cookie_session_is_encrypted_and_tamper_proof(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    response = login(client, "ceo@example.com")
    assert response.status_code == 303
    cookie = client.cookies.get("white_session")
    assert cookie and not any(token in cookie for token in supa.access)  # tokens are not readable
    assert client.get("/dashboard").status_code == 200
    client.cookies.set("white_session", cookie[:-4] + "AAAA")
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_sign_out_revokes_stateless_session(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    old = client.cookies.get("white_session")
    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    client.app.state.services._validated.clear()  # no cached validation: ask Supabase again
    client.cookies.set("white_session", old)
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_refreshed_tokens_are_written_back_to_the_cookie(tmp_path, supa):
    supa.access_ttl = 30  # inside the refresh margin -> refresh on next request
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    before = client.cookies.get("white_session")
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "white_session=" in response.headers.get("set-cookie", "")
    assert client.cookies.get("white_session") != before


def test_forged_domain_row_is_not_trusted(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    token = csrf(client, "/domains")
    client.post("/domains", data={"csrf_token": token, "hostname": "shop.example.com"})
    # A user editing their own row through the public API cannot produce a valid signature.
    row = supa.tables["verified_domains"][0]
    row.update({"verified_at": "2026-10-13T10:00:00+00:00", "method": "dns", "signature": "0" * 64})
    response = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 403 and response.json()["code"] == "domain_unverified"


def test_request_scoped_scan_end_to_end(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    verify_domain(client, supa, "ceo@example.com")
    token = csrf(client)
    created = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    )
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]
    status = client.get(f"/api/scans/{scan_id}/status").json()
    assert status["state"] == "queued" and status["run_required"] is True
    page = client.get(f"/scans/{scan_id}").text
    assert 'data-run="yes"' in page
    # A second scan cannot start while one is pending.
    busy = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    )
    assert busy.status_code == 409
    ran = client.post(f"/api/scans/{scan_id}/run", headers={"X-CSRF-Token": token})
    assert ran.status_code == 200 and ran.json()["state"] == "completed"
    row = next(r for r in supa.tables["scans"] if r["id"] == scan_id)
    assert row["progress"]["completed"] == row["progress"]["total"] == 21
    assert client.post(f"/api/scans/{scan_id}/run", headers={"X-CSRF-Token": token}).status_code == 409
    assert client.get(f"/scans/{scan_id}/report.pdf").content.startswith(b"%PDF")
    assert "Security report: shop.example.com" in client.get(f"/scans/{scan_id}").text


def test_other_users_cannot_run_or_see_a_scan(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    verify_domain(client, supa, "ceo@example.com")
    scan_id = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": csrf(client)},
    ).json()["scan_id"]
    from fastapi.testclient import TestClient

    other = TestClient(client.app, base_url="http://127.0.0.1:8000")
    login(other, "other@example.com", ip="203.0.113.99")
    assert other.post(f"/api/scans/{scan_id}/run", headers={"X-CSRF-Token": csrf(other)}).status_code == 404
    assert other.get(f"/api/scans/{scan_id}/status").status_code == 404
    assert other.get("/domains").text.count("shop.example.com") == 0


def test_cancel_queued_scan(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    verify_domain(client, supa, "ceo@example.com")
    token = csrf(client)
    scan_id = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    ).json()["scan_id"]
    assert client.post(f"/api/scans/{scan_id}/cancel", headers={"X-CSRF-Token": token}).status_code == 200
    assert client.get(f"/api/scans/{scan_id}/status").json()["state"] == "cancelled"


def test_rate_limit_uses_forwarded_client_ip(tmp_path, supa):
    client = serverless_client(tmp_path, supa, WHITE_TRUST_PROXY_HEADERS="true")
    for _ in range(10):
        login(client, "ceo@example.com", "wrong-password", ip="198.51.100.1")
    assert login(client, "ceo@example.com", "wrong-password", ip="198.51.100.1").status_code == 429
    # A different visitor behind the same proxy is not locked out.
    assert login(client, "ceo@example.com", ip="198.51.100.2").status_code == 303


def test_unknown_scan_run_returns_404(tmp_path, supa):
    client = serverless_client(tmp_path, supa)
    login(client, "ceo@example.com")
    r = client.post(f"/api/scans/{uuid.uuid4()}/run", headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 404

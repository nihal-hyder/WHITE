"""Operator admin console: login gating, credentials, and user/scan listing."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.conftest import FAKE_SERVICE_KEY, FakeSupabase, csrf, make_client, wait_for_scan
from white.auth.passwords import hash_password, verify_password


def admin_login(client, username="nihal", password="nihal"):
    token = csrf(client, "/admin/login")
    return client.post(
        "/admin/login",
        data={"csrf_token": token, "username": username, "password": password},
        follow_redirects=False,
    )


def test_password_hashing_roundtrip():
    h = hash_password("nihal")
    assert h.startswith("pbkdf2_sha256$") and verify_password("nihal", h)
    assert not verify_password("Nihal", h) and not verify_password("", h)
    assert not verify_password("x", "garbage")


def test_admin_requires_login(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/admin", follow_redirects=False).status_code == 303
    assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"
    assert client.get("/admin/login").status_code == 200


def test_admin_login_flow_and_logout(tmp_path):
    client = make_client(tmp_path)
    bad = admin_login(client, password="wrong")
    assert bad.status_code == 401 and "Incorrect" in bad.text
    assert client.get("/admin", follow_redirects=False).status_code == 303

    ok = admin_login(client)
    assert ok.status_code == 303 and ok.headers["location"] == "/admin"
    cookie = ok.headers["set-cookie"]
    assert "white_admin=" in cookie and "HttpOnly" in cookie and "Path=/admin" in cookie

    dash = client.get("/admin")
    assert dash.status_code == 200 and "Operator console" in dash.text and "Recent scans" in dash.text

    token = csrf(client, "/admin")
    out = client.post("/admin/logout", data={"csrf_token": token}, follow_redirects=False)
    assert out.status_code == 303 and out.headers["location"] == "/admin/login"
    assert client.get("/admin", follow_redirects=False).status_code == 303


def test_admin_rate_limited(tmp_path):
    client = make_client(tmp_path)
    for _ in range(8):
        admin_login(client, password="wrong")
    limited = admin_login(client, password="wrong")
    assert limited.status_code == 429


def test_admin_custom_credentials(tmp_path):
    client = make_client(tmp_path, WHITE_ADMIN_USER="root", WHITE_ADMIN_PASSWORD="s3cret-demo")
    assert admin_login(client, "nihal", "nihal").status_code == 401  # default no longer works
    assert admin_login(client, "root", "s3cret-demo").status_code == 303
    # no default-password warning banner when a custom password is set via hash
    client2 = make_client(tmp_path, WHITE_ADMIN_PASSWORD_HASH=hash_password("strongpass"))
    admin_login(client2, "nihal", "strongpass")
    assert "default password" not in client2.get("/admin").text


def test_admin_can_be_disabled(tmp_path):
    client = make_client(tmp_path, WHITE_ADMIN_ENABLED="false")
    assert client.get("/admin/login").status_code == 404
    assert client.get("/admin", follow_redirects=False).status_code == 404


def test_admin_local_mode_shows_scans_but_no_users(tmp_path):
    client = make_client(tmp_path)
    token = csrf(client)
    scan_id = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    ).json()["scan_id"]
    wait_for_scan(client, scan_id)
    admin_login(client)
    html = client.get("/admin").text
    assert "shop.example.com" in html
    # local mode: no registered-user data, with guidance on enabling it
    assert "Registered-user data" in html and "WHITE_SUPABASE_SERVICE_KEY" in html


def test_admin_cross_user_lists_everyone(tmp_path):
    supa = FakeSupabase()
    uid_a = supa.add_user("alice@example.com", "pw")
    uid_b = supa.add_user("bob@example.com", "pw")
    now = datetime.now(UTC).isoformat()
    supa.tables["scans"].extend(
        [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "user_id": uid_a,
                "target_url": "https://a.example.com/",
                "hostname": "a.example.com",
                "state": "completed",
                "created_at": now,
                "finished_at": now,
                "findings_total": 7,
                "high_priority": 2,
            },
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "user_id": uid_b,
                "target_url": "https://b.example.com/",
                "hostname": "b.example.com",
                "state": "completed",
                "created_at": now,
                "finished_at": now,
                "findings_total": 3,
                "high_priority": 0,
            },
        ]
    )
    client = make_client(tmp_path, supabase=supa, WHITE_SUPABASE_SERVICE_KEY=FAKE_SERVICE_KEY)
    admin_login(client)
    html = client.get("/admin").text
    # both users and both scans visible across accounts
    assert "alice@example.com" in html and "bob@example.com" in html
    assert "a.example.com" in html and "b.example.com" in html
    assert "Registered users" in html
    assert "Registered-user data" not in html  # the local-only guidance is gone


def test_service_key_never_sent_to_browser(tmp_path):
    supa = FakeSupabase()
    supa.add_user("alice@example.com", "pw")
    client = make_client(tmp_path, supabase=supa, WHITE_SUPABASE_SERVICE_KEY=FAKE_SERVICE_KEY)
    admin_login(client)
    assert FAKE_SERVICE_KEY not in client.get("/admin").text

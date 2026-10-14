"""Web GUI and API in local mode (no Supabase): pages, CSRF, scans, reports, headers."""

from __future__ import annotations

import json
import re

from tests.conftest import csrf, make_client, wait_for_scan


def start(client, url="https://shop.example.com/", **extra):
    token = csrf(client)
    body = {"url": url, "authorized": True, **extra}
    return client.post("/api/scans", json=body, headers={"X-CSRF-Token": token})


def test_health_has_no_secrets(tmp_path):
    client = make_client(tmp_path)
    data = client.get("/api/health").json()
    assert data == {"status": "ok", "version": data["version"], "mode": "local"}


def test_pages_render_with_security_headers(tmp_path):
    client = make_client(tmp_path)
    for path in ["/", "/dashboard", "/scans/new", "/history", "/settings", "/domains"]:
        response = client.get(path)
        assert response.status_code == 200, path
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"
    assert "No scans yet" in client.get("/dashboard").text
    assert client.get("/login", follow_redirects=False).status_code == 303  # accounts disabled


def test_unknown_host_header_rejected(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/api/health", headers={"host": "attacker.example"}).status_code == 400


def test_csrf_required_for_state_changes(tmp_path):
    client = make_client(tmp_path)
    assert (
        client.post("/api/scans", json={"url": "https://shop.example.com", "authorized": True}).status_code
        == 403
    )
    client.get("/")
    bad = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": "forged"},
    )
    assert bad.status_code == 403
    token = csrf(client)
    cross = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token, "Origin": "https://evil.example"},
    )
    assert cross.status_code == 403


def test_scan_requires_authorization_and_valid_target(tmp_path):
    client = make_client(tmp_path)
    token = csrf(client)
    r = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": False},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 400 and r.json()["code"] == "authorization"
    r = client.post(
        "/api/scans", json={"url": "http://127.0.0.1/", "authorized": True}, headers={"X-CSRF-Token": token}
    )
    assert r.status_code == 400 and r.json()["code"] == "target"
    r = client.post(
        "/api/scans", json={"url": "file:///etc/passwd", "authorized": True}, headers={"X-CSRF-Token": token}
    )
    assert r.status_code == 400


def test_full_scan_flow_and_downloads(tmp_path):
    client = make_client(tmp_path)
    response = start(client)
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    status = wait_for_scan(client, scan_id)
    assert status["state"] == "completed" and status["completed_checks"] == 21
    page = client.get(f"/scans/{scan_id}")
    assert "Security report: shop.example.com" in page.text
    findings = client.get(f"/api/scans/{scan_id}/findings").json()
    assert isinstance(findings, list)
    for fmt, prefix in (("json", b"{"), ("pdf", b"%PDF"), ("html", b"<!doctype html>")):
        download = client.get(f"/scans/{scan_id}/report.{fmt}")
        assert download.status_code == 200 and download.content.startswith(prefix)
        assert re.match(
            r'attachment; filename="white-report-shop\.example\.com-\d{8}-\d{4}\.' + fmt + '"',
            download.headers["content-disposition"],
        )
    assert client.get(f"/scans/{scan_id}/report.exe").status_code in {404, 422}
    history = client.get("/history").text
    assert "shop.example.com" in history
    dashboard = client.get("/dashboard").text
    assert "chart-data" in dashboard and "Trends need at least two completed scans" in dashboard


def test_duplicate_submission_rejected(tmp_path):
    client = make_client(tmp_path)
    first = start(client)
    wait_for_scan(client, first.json()["scan_id"])
    second = start(client)
    assert second.status_code == 409


def test_dashboard_chart_data_matches_report(tmp_path):
    client = make_client(tmp_path)
    scan_id = start(client).json()["scan_id"]
    wait_for_scan(client, scan_id)
    data = client.get("/api/dashboard").json()
    report = client.get(f"/api/scans/{scan_id}").json()["report"]
    assert sum(data["severity"]["values"]) == report["summary"]["findings_total"]
    assert sum(data["coverage"]["values"]) == len(report["checks"])
    assert data["trend"]["enough_data"] is False
    html = client.get("/dashboard").text
    payload = re.search(r'<script id="chart-data" type="application/json">(.*?)</script>', html, re.S).group(
        1
    )
    assert json.loads(payload)["latest"]["scan_id"] == scan_id


def test_missing_and_malformed_ids_return_404(tmp_path):
    client = make_client(tmp_path)
    for path in [
        "/scans/00000000-0000-0000-0000-000000000000",
        "/scans/../../etc/passwd",
        "/api/scans/not-a-uuid/status",
        "/scans/x/report.pdf",
    ]:
        assert client.get(path).status_code == 404, path


def test_delete_scan(tmp_path):
    client = make_client(tmp_path)
    scan_id = start(client).json()["scan_id"]
    wait_for_scan(client, scan_id)
    token = csrf(client)
    response = client.post(f"/scans/{scan_id}/delete", data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303
    assert client.get(f"/api/scans/{scan_id}/status").status_code == 404


def test_html_form_scan_with_escaping(tmp_path):
    client = make_client(tmp_path)
    token = csrf(client)
    evil = "https://shop.example.com/<script>alert(1)</script>"
    response = client.post("/scans", data={"csrf_token": token, "url": evil}, follow_redirects=False)
    assert response.status_code == 400  # authorization not confirmed
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_domain_verification_enforced_when_enabled(tmp_path):
    client = make_client(tmp_path, WHITE_REQUIRE_DOMAIN_VERIFICATION="true")
    response = start(client)
    assert response.status_code == 403 and response.json()["code"] == "domain_unverified"
    token = csrf(client, "/domains")
    client.post("/domains", data={"csrf_token": token, "hostname": "shop.example.com"})
    page = client.get("/domains").text
    assert "_white-verify.shop.example.com" in page and "white-verify=" in page
    services = client.app.state.services
    record = services.domains.get_by_host("local", "shop.example.com")
    services.domains.mark_verified("local", record.id, "dns")
    assert start(client).status_code == 202


def test_domain_rejects_private_hosts(tmp_path):
    client = make_client(tmp_path, WHITE_REQUIRE_DOMAIN_VERIFICATION="true")
    token = csrf(client, "/domains")
    response = client.post("/domains", data={"csrf_token": token, "hostname": "localhost"})
    assert response.status_code == 400


def test_custom_error_pages(tmp_path):
    client = make_client(tmp_path)
    r = client.get("/no-such-page-here")
    assert r.status_code == 404
    assert "text/html" in r.headers["content-type"]
    assert "Page not found" in r.text and "404" in r.text
    # API paths still return JSON, not the HTML page
    j = client.get("/api/no-such-endpoint")
    assert j.status_code == 404 and j.headers["content-type"].startswith("application/json")
    # an unexpected server error shows the friendly page without leaking details
    app = client.app

    @app.get("/_boom_test")
    def _boom():
        raise RuntimeError("secret internal detail")

    from fastapi.testclient import TestClient

    safe = TestClient(app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False)
    r = safe.get("/_boom_test")
    assert r.status_code == 500 and "Something went wrong" in r.text and "secret internal detail" not in r.text

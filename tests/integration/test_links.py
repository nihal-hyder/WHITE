"""Every internal link and form target on every page must resolve (no 404/500)."""

from __future__ import annotations

import re
from urllib.parse import urldefrag, urljoin, urlsplit

from tests.conftest import FakeSupabase, make_client, wait_for_scan

HREF = re.compile(r'(?:href|action)="([^"]+)"')


def crawl(client, start_pages):
    seen, queue, failures = set(), list(start_pages), []
    while queue:
        page = queue.pop()
        if page in seen:
            continue
        seen.add(page)
        response = client.get(page)
        if response.status_code >= 400:
            failures.append((page, response.status_code))
            continue
        if "text/html" not in response.headers.get("content-type", ""):
            continue
        html = response.text
        for raw in HREF.findall(html):
            url, fragment = urldefrag(urljoin("http://127.0.0.1:8000" + page, raw.replace("&amp;", "&")))
            parts = urlsplit(url)
            if parts.netloc != "127.0.0.1:8000" or parts.path.startswith("/static/"):
                if parts.path.startswith("/static/"):
                    assert client.get(parts.path).status_code == 200, parts.path
                continue
            path = parts.path + (f"?{parts.query}" if parts.query else "")
            if fragment:
                target = client.get(parts.path).text
                assert f'id="{fragment}"' in target, (
                    f"missing anchor #{fragment} on {parts.path} (from {page})"
                )
            # Form actions are POST-only; just make sure the route exists (not 404).
            if f'action="{raw}"' in html:
                status = client.post(path).status_code
                assert status != 404, f"form action {path} not found (from {page})"
                continue
            if path not in seen and "/report." not in path and "/logout" not in path:
                queue.append(path)
    return seen, failures


def test_all_links_resolve_in_local_mode(tmp_path):
    client = make_client(tmp_path)
    from tests.conftest import csrf

    token = csrf(client)
    scan_id = client.post(
        "/api/scans",
        json={"url": "https://shop.example.com", "authorized": True},
        headers={"X-CSRF-Token": token},
    ).json()["scan_id"]
    wait_for_scan(client, scan_id)
    seen, failures = crawl(client, ["/", "/dashboard", "/history", f"/scans/{scan_id}"])
    assert not failures, failures
    for page in [
        "/",
        "/security",
        "/privacy",
        "/acceptable-use",
        "/dashboard",
        "/scans/new",
        "/history",
        "/settings",
    ]:
        assert page in seen


def test_public_pages_and_footer_in_accounts_mode(tmp_path):
    client = make_client(tmp_path, supabase=FakeSupabase())
    seen, failures = crawl(client, ["/", "/login", "/signup", "/security", "/privacy", "/acceptable-use"])
    # Protected pages redirect to sign-in rather than failing.
    assert not failures, failures
    home = client.get("/").text
    for text in ("How it works", "What we check", "FAQ", "Privacy", "Acceptable use", "Get started"):
        assert text in home


def test_homepage_content_is_honest(tmp_path):
    client = make_client(tmp_path)
    html = client.get("/").text
    from white.scanner.registry import all_checks

    assert f">{len(all_checks())}<" in html  # the check count shown is the real registry size
    for check in all_checks():
        assert check.name in html  # coverage section is generated from the registry
    assert "Illustrative example" in html and "Example" in html  # sample findings are labelled
    assert "100% secure" not in html.replace('never claims "100% secure"', "")

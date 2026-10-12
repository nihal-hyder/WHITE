"""Individual checks against controlled mock responses."""

from __future__ import annotations

import httpx

from tests.conftest import GOOD_HTML, SECURE_HEADERS, MockSite, good_site, run_scan
from white.scanner.checks.cookies import parse_set_cookie
from white.scanner.checks.headers import parse_csp
from white.scanner.models import CheckStatus, Severity

HOST = "shop.example.com"
BASE = f"https://{HOST}/"


def result(report, check_id):
    return next(c for c in report.checks if c.check_id == check_id)


def site_with(headers=None, html=GOOD_HTML, extra=None, http_redirect=True) -> MockSite:
    routes = {BASE: (200, headers if headers is not None else SECURE_HEADERS, html)}
    routes[f"http://{HOST}/"] = (
        (301, {"location": BASE}, b"") if http_redirect else (200, {"content-type": "text/html"}, html)
    )
    routes.update(extra or {})
    return MockSite(routes)


def test_well_configured_site_passes_header_checks():
    report = run_scan(good_site())
    for check_id in [
        "https-availability",
        "http-to-https-redirect",
        "hsts",
        "content-security-policy",
        "clickjacking-protection",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "server-identification",
        "mixed-content",
        "public-file-exposure",
        "directory-listing",
        "information-disclosure",
    ]:
        assert result(report, check_id).status == CheckStatus.PASS, check_id
    assert result(report, "cookie-security").status == CheckStatus.NOT_APPLICABLE
    assert result(report, "form-security").status == CheckStatus.NOT_APPLICABLE


def test_missing_headers_produce_findings_with_evidence():
    report = run_scan(site_with(headers={"content-type": "text/html"}))
    csp = result(report, "content-security-policy")
    assert csp.status == CheckStatus.FINDING
    assert csp.findings[0].severity == Severity.MEDIUM
    assert any(e.label == "Content-Security-Policy" for e in csp.findings[0].evidence)
    assert result(report, "hsts").findings[0].severity == Severity.LOW
    assert result(report, "clickjacking-protection").status == CheckStatus.FINDING
    assert result(report, "x-content-type-options").status == CheckStatus.FINDING
    assert result(report, "referrer-policy").findings[0].severity == Severity.INFO


def test_weak_csp_and_short_hsts():
    headers = dict(SECURE_HEADERS)
    headers["content-security-policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' *"
    headers["strict-transport-security"] = "max-age=300"
    report = run_scan(site_with(headers=headers))
    assert (
        result(report, "content-security-policy")
        .findings[0]
        .title.startswith("Content-Security-Policy allows")
    )
    assert result(report, "hsts").findings[0].id.startswith("hsts:")


def test_csp_parser():
    parsed = parse_csp("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic';")
    assert parsed["script-src"] == ["'nonce-abc'", "'strict-dynamic'"]


def test_server_version_disclosure():
    headers = dict(SECURE_HEADERS, server="Apache/2.4.41 (Ubuntu)", **{"x-powered-by": "PHP/7.4.3"})
    finding = result(run_scan(site_with(headers=headers)), "server-identification").findings[0]
    assert finding.severity == Severity.LOW
    assert {e.label for e in finding.evidence} == {"server", "x-powered-by"}


def test_http_not_redirected():
    report = run_scan(site_with(http_redirect=False))
    assert result(report, "http-to-https-redirect").status == CheckStatus.FINDING


def test_https_unavailable_is_high():
    site = MockSite({f"http://{HOST}/": (200, {"content-type": "text/html"}, GOOD_HTML)})
    site.errors[BASE] = httpx.ConnectError("refused")
    report = run_scan(site, url=f"http://{HOST}/")
    finding = result(report, "https-availability").findings[0]
    assert finding.severity == Severity.HIGH
    assert result(report, "hsts").status == CheckStatus.NOT_APPLICABLE


def test_untrusted_certificate():
    site = MockSite()
    site.errors[BASE] = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed")
    site.errors[f"http://{HOST}/"] = httpx.ConnectError("refused")
    report = run_scan(site)
    assert result(report, "https-availability").findings[0].title == "HTTPS certificate is not trusted"


def test_cookie_parsing_never_keeps_values():
    cookie = parse_set_cookie("sessionid=SUPERSECRETVALUE; Path=/; HttpOnly; SameSite=Lax")
    assert cookie.name == "sessionid" and cookie.http_only and cookie.same_site == "lax"
    assert not cookie.secure and cookie.session_like
    assert "SUPERSECRETVALUE" not in cookie.raw


def test_cookie_check():
    headers = httpx.Headers(SECURE_HEADERS)
    headers = [(k, v) for k, v in SECURE_HEADERS.items()] + [
        ("set-cookie", "sessionid=abc123secret; Path=/"),
        ("set-cookie", "pref=dark; Secure; HttpOnly; SameSite=Strict"),
    ]
    site = MockSite({BASE: (200, headers, GOOD_HTML), f"http://{HOST}/": (301, {"location": BASE}, b"")})
    check = result(run_scan(site), "cookie-security")
    titles = {f.title: f for f in check.findings}
    assert check.status == CheckStatus.FINDING
    assert titles["Cookies can be sent over unencrypted connections"].severity == Severity.MEDIUM
    assert "Cookies do not declare a SameSite policy" in titles
    dumped = check.model_dump_json()
    assert "abc123secret" not in dumped


def test_mixed_content_and_forms():
    html = (
        "<html><body><script src='http://cdn.example.org/a.js'></script><img src='http://x.org/i.png'>"
        "<form action='http://shop.example.com/login' method='get'><input type='password' name='p'></form>"
        "</body></html>"
    )
    report = run_scan(site_with(html=html))
    mixed = {f.title: f.severity for f in result(report, "mixed-content").findings}
    assert mixed == {
        "Secure page loads scripts or styles over HTTP": Severity.MEDIUM,
        "Secure page loads images or media over HTTP": Severity.LOW,
    }
    forms = {f.title: f.severity for f in result(report, "form-security").findings}
    assert forms["Form sends information over an unencrypted connection"] == Severity.HIGH
    assert forms["Password form uses the GET method"] == Severity.LOW


def test_debug_page_on_404_detected():
    site = good_site()
    original = site.handler

    def handler(request):
        if "white-check-" in request.url.path:
            return httpx.Response(
                500,
                headers={"content-type": "text/html"},
                text="<pre>Traceback (most recent call last):\n  File app.py</pre>",
            )
        return original(request)

    site.handler = handler
    finding = result(run_scan(site), "information-disclosure").findings[0]
    assert finding.severity == Severity.MEDIUM and "Python traceback" in finding.title


def test_secret_comment_is_potential_and_redacted():
    html = "<html><body><!-- password = hunter2 --></body></html>"
    check = result(run_scan(site_with(html=html)), "information-disclosure")
    assert check.status == CheckStatus.POTENTIAL
    assert "hunter2" not in check.model_dump_json()


def test_directory_listing_detected():
    html = "<html><body><img src='/uploads/a.png'></body></html>"
    listing = (200, {"content-type": "text/html"}, "<html><title>Index of /uploads</title></html>")
    report = run_scan(site_with(html=html, extra={f"https://{HOST}/uploads/": listing}))
    assert result(report, "directory-listing").status == CheckStatus.FINDING


def test_env_file_exposure_is_critical_and_values_never_stored():
    env = "DB_PASSWORD=supersecret\nAPI_KEY=abcdef123\nDEBUG=true\n"
    report = run_scan(site_with(extra={f"https://{HOST}/.env": (200, {"content-type": "text/plain"}, env)}))
    finding = result(report, "public-file-exposure").findings[0]
    assert finding.severity == Severity.CRITICAL
    dumped = report.model_dump_json()
    assert "supersecret" not in dumped and "abcdef123" not in dumped
    assert "DB_PASSWORD" in dumped


def test_soft_404_does_not_create_false_positives():
    """A site that returns 200 HTML for every path must not be reported as exposing files."""
    site = good_site()

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=GOOD_HTML)

    site.handler = handler
    report = run_scan(site)
    assert result(report, "public-file-exposure").status == CheckStatus.PASS
    assert result(report, "robots-txt").status == CheckStatus.NOT_APPLICABLE
    assert result(report, "sitemap-xml").status == CheckStatus.NOT_APPLICABLE


def test_git_head_exposure():
    extra = {f"https://{HOST}/.git/HEAD": (200, {"content-type": "text/plain"}, "ref: refs/heads/main\n")}
    finding = result(run_scan(site_with(extra=extra)), "public-file-exposure").findings[0]
    assert finding.severity == Severity.HIGH


def test_robots_and_sitemap():
    robots = (
        "User-agent: *\nDisallow: /admin/\nDisallow: /cart\nSitemap: https://shop.example.com/sitemap.xml\n"
    )
    sitemap = (
        "<?xml version='1.0'?><urlset><url><loc>https://shop.example.com/</loc></url>"
        "<url><loc>https://shop.example.com/staging/home</loc></url></urlset>"
    )
    report = run_scan(
        site_with(
            extra={
                f"https://{HOST}/robots.txt": (200, {"content-type": "text/plain"}, robots),
                f"https://{HOST}/sitemap.xml": (200, {"content-type": "application/xml"}, sitemap),
            }
        )
    )
    robots_check = result(report, "robots-txt")
    assert robots_check.status == CheckStatus.POTENTIAL
    assert robots_check.findings[0].severity == Severity.INFO
    assert result(report, "sitemap-xml").status == CheckStatus.POTENTIAL


def test_active_checks_not_tested_by_default():
    report = run_scan(good_site())
    for check_id in ("reflected-xss-indicator", "sql-error-indicator"):
        assert result(report, check_id).status == CheckStatus.NOT_TESTED


def test_reflected_xss_indicator():
    def page(request):
        value = request.url.params.get("q", "")
        return f"<html><body>You searched for {value}</body></html>"

    site = MockSite(
        {
            f"https://{HOST}/search": (200, {"content-type": "text/html"}, page),
            f"http://{HOST}/search": (301, {"location": f"https://{HOST}/search?q=a"}, b""),
        }
    )
    report = run_scan(site, url=f"https://{HOST}/search?q=a", active_checks=True)
    check = result(report, "reflected-xss-indicator")
    assert check.status == CheckStatus.POTENTIAL
    assert all(r.method == "GET" for r in site.requests)


def test_escaped_reflection_passes():
    import html

    def page(request):
        return f"<html><body>{html.escape(request.url.params.get('q', ''))}</body></html>"

    site = MockSite({f"https://{HOST}/search": (200, {"content-type": "text/html"}, page)})
    report = run_scan(site, url=f"https://{HOST}/search?q=a", active_checks=True)
    assert result(report, "reflected-xss-indicator").status == CheckStatus.PASS


def test_sql_error_indicator():
    def page(request):
        if "'" in request.url.params.get("id", ""):
            return "<html>You have an error in your SQL syntax near ''1''</html>"
        return "<html>Product 1</html>"

    site = MockSite({f"https://{HOST}/item": (200, {"content-type": "text/html"}, page)})
    report = run_scan(site, url=f"https://{HOST}/item?id=1", active_checks=True)
    finding = result(report, "sql-error-indicator").findings[0]
    assert finding.status == CheckStatus.POTENTIAL and finding.severity == Severity.HIGH


def test_sql_check_not_applicable_without_parameters():
    report = run_scan(good_site(), active_checks=True)
    assert result(report, "sql-error-indicator").status == CheckStatus.NOT_APPLICABLE


def test_https_downgrade_redirect():
    site = MockSite(
        {
            BASE: (302, {"location": f"http://{HOST}/home"}, b""),
            f"http://{HOST}/home": (200, {"content-type": "text/html"}, GOOD_HTML),
            f"http://{HOST}/": (200, {"content-type": "text/html"}, GOOD_HTML),
        }
    )
    findings = result(run_scan(site), "redirect-behaviour").findings
    assert any(f.title == "Redirect downgrades from HTTPS to HTTP" for f in findings)

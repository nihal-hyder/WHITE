"""JSON/HTML/PDF report generation, escaping and redaction."""

from __future__ import annotations

import json

import pytest

from tests.conftest import MockSite, run_scan
from white.reporting.html_report import build_html
from white.reporting.json_report import ReportLoadError, load_report, load_report_text, to_json
from white.reporting.pdf_report import build_pdf
from white.scanner.models import Evidence
from white.scanner.redact import redact_cookie, redact_text, redact_url

XSS = "<script>alert('x')</script>"


def _report():
    long_path = "/" + "very-long-segment-" * 30
    site = MockSite(
        {
            f"https://shop.example.com{long_path}": (
                200,
                {"content-type": "text/html", "server": "Apache/2.4.1"},
                "<html><body><form action='http://x.example.com/'></form></body></html>",
            ),
            f"http://shop.example.com{long_path}": (
                301,
                {"location": f"https://shop.example.com{long_path}"},
                b"",
            ),
        }
    )
    report = run_scan(site, url=f"https://shop.example.com{long_path}")
    report.findings[0].evidence.append(Evidence(label="Injected", value=XSS))
    return report


def test_json_round_trip(tmp_path):
    report = _report()
    text = to_json(report)
    data = json.loads(text)
    assert data["tool"] == "WHITE" and data["schema_version"] == "1.0"
    assert len(data["findings_flat"]) == report.summary.findings_total
    path = tmp_path / "r.json"
    path.write_text(text, encoding="utf-8")
    loaded = load_report(path)
    assert loaded.scan_id == report.scan_id
    assert loaded.summary.findings_total == report.summary.findings_total


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        '{"tool": "OTHER"}',
        '{"tool": "WHITE", "schema_version": "9.0"}',
        '{"tool": "WHITE", "schema_version": "1.0"}',
    ],
)
def test_invalid_reports_rejected(text):
    with pytest.raises(ReportLoadError):
        load_report_text(text)


def test_html_report_escapes_content():
    html = build_html(_report())
    assert XSS not in html
    assert "&lt;script&gt;" in html
    assert "<script" not in html.lower()  # standalone report contains no scripts at all


def test_pdf_report_is_valid_and_multipage():
    pdf = build_pdf(_report())
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    assert pdf.count(b"/Type /Page") - pdf.count(b"/Type /Pages") >= 2


def test_pdf_for_failed_scan():
    site = MockSite()
    import httpx

    site.errors["https://shop.example.com/"] = httpx.ConnectError("refused")
    site.errors["http://shop.example.com/"] = httpx.ConnectError("refused")
    assert build_pdf(run_scan(site)).startswith(b"%PDF-")


def test_redaction():
    assert "[REDACTED-JWT]" in redact_text(
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
    )
    assert "hunter2" not in redact_text("password=hunter2")
    assert "AKIA" not in redact_text("key AKIAABCDEFGHIJKLMNOP")
    assert len(redact_text("x" * 1000)) <= 300
    assert (
        redact_url("https://u:p@example.com/a?token=abc&q=1")
        == "https://example.com/a?token=%5BREDACTED%5D&q=1"
    )
    assert redact_cookie("sid=abc; Secure") == "sid=[value hidden]; Secure"

"""Scan engine states, finding model, summaries, history comparison and chart data."""

from __future__ import annotations

import threading
from datetime import timedelta

import httpx
import pytest

from tests.conftest import SECURE_HEADERS, MockSite, good_site, run_scan
from white.reporting import analytics
from white.scanner.checks.base import Check, Outcome
from white.scanner.engine import Scanner
from white.scanner.models import Category, CheckStatus, Finding, ScanConfig, ScanState
from white.scanner.netsafety import TargetValidationError


def test_completed_scan_summary_is_consistent():
    site = MockSite(
        {
            "https://shop.example.com/": (200, {"content-type": "text/html"}, "<html></html>"),
            "http://shop.example.com/": (301, {"location": "https://shop.example.com/"}, b""),
        }
    )
    report = run_scan(site)
    assert report.state == ScanState.COMPLETED
    s = report.summary
    assert s.checks_total == len(report.checks) == 21
    assert sum(s.status_counts.values()) == s.checks_total
    assert s.findings_total == len(report.findings) == s.severity_counts.total
    assert sum(s.category_counts.values()) == s.findings_total
    assert report.finished_at >= report.started_at and report.duration_seconds >= 0


def test_unreachable_target_fails_and_is_not_successful():
    site = MockSite()
    site.errors["https://shop.example.com/"] = httpx.ConnectError("refused")
    site.errors["http://shop.example.com/"] = httpx.ConnectError("refused")
    report = run_scan(site)
    assert report.state == ScanState.FAILED
    assert report.summary.findings_total == 0
    assert any("unreachable" in e for e in report.errors)
    assert analytics.overall_assessment(report)[0] == "Assessment incomplete"


def test_invalid_target_raises_before_network():
    site = good_site()
    with pytest.raises(TargetValidationError):
        Scanner(ScanConfig(), transport=site.transport).run("http://10.0.0.1/")
    assert site.requests == []


def test_crashing_check_is_recorded_as_error():
    class Broken(Check):
        id, name, category, description = "broken", "Broken", Category.CONFIGURATION, "x"

        def evaluate(self, ctx):
            raise RuntimeError("boom")

    class Fine(Check):
        id, name, category, description = "fine", "Fine", Category.CONFIGURATION, "x"

        def evaluate(self, ctx):
            return Outcome(CheckStatus.PASS, "ok")

    report = Scanner(
        ScanConfig(min_request_interval=0), checks=[Broken(), Fine()], transport=good_site().transport
    ).run("https://shop.example.com/")
    assert report.state == ScanState.COMPLETED_WITH_ERRORS
    assert report.checks[0].status == CheckStatus.ERROR and "boom" in report.checks[0].errors[0]
    assert report.checks[1].status == CheckStatus.PASS


def test_cancellation_marks_remaining_checks_not_tested():
    event = threading.Event()
    calls = []

    class Canceller(Check):
        id, name, category, description = "c", "C", Category.CONFIGURATION, "x"

        def evaluate(self, ctx):
            calls.append(1)
            event.set()
            return Outcome(CheckStatus.PASS, "ok")

    report = Scanner(
        ScanConfig(min_request_interval=0), checks=[Canceller(), Canceller()], transport=good_site().transport
    ).run("https://shop.example.com/", cancel_event=event)
    assert report.state == ScanState.CANCELLED
    assert report.checks[1].status == CheckStatus.NOT_TESTED and len(calls) == 1


def test_request_budget_exhaustion_is_reported():
    report = run_scan(good_site(), max_requests=3)
    assert report.state == ScanState.COMPLETED_WITH_ERRORS
    assert any(c.status == CheckStatus.NOT_TESTED and "limit" in c.message for c in report.checks)


def test_progress_reports_real_counts():
    seen = []
    Scanner(ScanConfig(min_request_interval=0), transport=good_site().transport).run(
        "https://shop.example.com/", progress=seen.append
    )
    assert seen[0].completed == 0 and seen[-1].completed == seen[-1].total == 21
    assert [p.completed for p in seen] == sorted(p.completed for p in seen)


def test_fingerprint_is_stable_and_host_specific():
    a = Finding.fingerprint("hsts", "hsts-missing", "Example.com")
    assert a == Finding.fingerprint("hsts", "hsts-missing", "example.com")
    assert a != Finding.fingerprint("hsts", "hsts-missing", "other.com")


def _bad_site():
    return MockSite(
        {
            "https://shop.example.com/": (200, {"content-type": "text/html"}, "<html></html>"),
            "http://shop.example.com/": (301, {"location": "https://shop.example.com/"}, b""),
        }
    )


def test_history_comparison_new_unresolved_fixed():
    first = run_scan(_bad_site())
    second = run_scan(good_site())
    second.started_at = first.started_at + timedelta(hours=1)
    comparison = analytics.compare(second, first)
    assert comparison.available
    assert len(comparison.fixed) == first.summary.findings_total
    assert comparison.new == [] and comparison.unverified == []


def test_fixed_requires_completed_check():
    first = run_scan(_bad_site())
    site = good_site()
    site.errors["https://shop.example.com/"] = httpx.ConnectError("refused")
    site.errors["http://shop.example.com/"] = httpx.ConnectError("refused")
    failed = run_scan(site)
    comparison = analytics.compare(failed, first)
    assert comparison.fixed == []
    assert len(comparison.unverified) == first.summary.findings_total


def test_find_previous_ignores_failed_and_other_targets():
    a = run_scan(_bad_site())
    b = run_scan(good_site())
    b.started_at = a.started_at + timedelta(minutes=5)
    other = run_scan(good_site("other.example.com"), url="https://other.example.com/")
    assert analytics.find_previous(b, [a, b, other]).scan_id == a.scan_id
    assert analytics.find_previous(a, [a, b, other]) is None


def test_trend_chart_requires_two_scans():
    a = run_scan(_bad_site())
    trend = analytics.trend_chart([a])
    assert not trend["enough_data"] and trend["points"][0]["baseline"]
    b = run_scan(good_site())
    b.started_at = a.started_at + timedelta(hours=1)
    trend = analytics.trend_chart([b, a])
    assert trend["enough_data"]
    assert trend["points"][1]["fixed"] == a.summary.findings_total


def test_chart_data_matches_summary():
    report = run_scan(_bad_site())
    sev = analytics.severity_chart(report)
    assert sum(sev["values"]) == report.summary.findings_total
    assert sev["keys"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert sum(analytics.category_chart(report)["values"]) == report.summary.findings_total
    assert sum(analytics.coverage_chart(report)["values"]) == report.summary.checks_total


def test_actions_are_prioritised_by_severity():
    report = run_scan(_bad_site())
    actions = analytics.prioritized_actions(report, limit=20)
    ranks = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    order = [ranks.index(a["severity"]) for a in actions]
    assert order == sorted(order)


def test_summary_never_claims_secure():
    report = run_scan(
        MockSite(
            {
                "https://shop.example.com/": (200, SECURE_HEADERS, "<html></html>"),
                "http://shop.example.com/": (301, {"location": "https://shop.example.com/"}, b""),
            }
        )
    )
    text = analytics.executive_summary(report).lower()
    label = analytics.overall_assessment(report)[0].lower()
    assert "does not mean the website is secure" in text or report.summary.findings_total
    assert "secure" not in label

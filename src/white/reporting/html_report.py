"""Standalone HTML report (no JavaScript, no external resources, auto-escaped)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from white.reporting import analytics
from white.scanner.models import STATUS_LABELS, ScanReport

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"], default=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def build_html(report: ScanReport, comparison: analytics.Comparison | None = None) -> str:
    label, tone = analytics.overall_assessment(report)
    return _env.get_template("report.html").render(
        report=report,
        findings=report.findings,
        summary_text=analytics.executive_summary(report),
        assessment=label,
        tone=tone,
        actions=analytics.prioritized_actions(report),
        severity=analytics.severity_chart(report),
        categories=analytics.category_chart(report),
        coverage=analytics.coverage_chart(report),
        comparison=comparison,
        status_labels=STATUS_LABELS,
    )

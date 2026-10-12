"""Derived data for dashboards, charts and reports. Every number comes from real scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from white.scanner.models import (
    CATEGORY_LABELS,
    SEVERITY_ORDER,
    STATUS_LABELS,
    Category,
    CheckStatus,
    Finding,
    ScanReport,
    ScanState,
)

COMPARABLE_STATES = {ScanState.COMPLETED, ScanState.COMPLETED_WITH_ERRORS}


def comparable_key(report: ScanReport) -> str:
    """Scans are comparable when they target the same scheme/host/port/path."""
    parts = urlsplit(report.target_url)
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}".lower()


@dataclass
class Comparison:
    previous_scan_id: str | None
    new: list[Finding] = field(default_factory=list)
    unresolved: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    unverified: list[Finding] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return self.previous_scan_id is not None

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "unresolved": len(self.unresolved),
            "fixed": len(self.fixed),
            "unverified": len(self.unverified),
        }


def compare(current: ScanReport, previous: ScanReport | None) -> Comparison:
    """Compare two comparable scans by stable finding fingerprints.

    A previous finding counts as *fixed* only when the current scan completed and the same check
    ran to a conclusion (PASS, FINDING or POTENTIAL) without reproducing it. If the check errored,
    was skipped, was inconclusive or was not applicable (e.g. HTTPS was unreachable), the finding
    is *unverified* rather than fixed.
    """
    if previous is None:
        return Comparison(previous_scan_id=None, new=list(current.findings))
    result = Comparison(previous_scan_id=previous.scan_id)
    current_ids = {f.id for f in current.findings}
    previous_ids = {f.id for f in previous.findings}
    check_status = {c.check_id: c.status for c in current.checks}
    for finding in current.findings:
        (result.unresolved if finding.id in previous_ids else result.new).append(finding)
    for finding in previous.findings:
        if finding.id in current_ids:
            continue
        status = check_status.get(finding.check_id)
        completed = current.state in COMPARABLE_STATES and status in {
            CheckStatus.PASS,
            CheckStatus.FINDING,
            CheckStatus.POTENTIAL,
        }
        (result.fixed if completed else result.unverified).append(finding)
    return result


def find_previous(current: ScanReport, history: list[ScanReport]) -> ScanReport | None:
    """Most recent earlier comparable scan of the same target."""
    key = comparable_key(current)
    earlier = [
        r
        for r in history
        if r.scan_id != current.scan_id
        and r.state in COMPARABLE_STATES
        and comparable_key(r) == key
        and r.started_at < current.started_at
    ]
    return max(earlier, key=lambda r: r.started_at, default=None)


def severity_chart(report: ScanReport) -> dict:
    counts = report.summary.severity_counts
    return {
        "labels": [s.label for s in SEVERITY_ORDER],
        "keys": [s.value for s in SEVERITY_ORDER],
        "values": [getattr(counts, s.value) for s in SEVERITY_ORDER],
    }


def category_chart(report: ScanReport) -> dict:
    return {
        "labels": [CATEGORY_LABELS[c] for c in Category],
        "keys": [c.value for c in Category],
        "values": [report.summary.category_counts.get(c.value, 0) for c in Category],
    }


COVERAGE_ORDER = [
    CheckStatus.PASS,
    CheckStatus.FINDING,
    CheckStatus.POTENTIAL,
    CheckStatus.INCONCLUSIVE,
    CheckStatus.NOT_APPLICABLE,
    CheckStatus.NOT_TESTED,
    CheckStatus.ERROR,
]


def coverage_chart(report: ScanReport) -> dict:
    return {
        "labels": [STATUS_LABELS[s] for s in COVERAGE_ORDER],
        "keys": [s.value for s in COVERAGE_ORDER],
        "values": [report.summary.status_counts.get(s.value, 0) for s in COVERAGE_ORDER],
    }


def trend_chart(history: list[ScanReport]) -> dict:
    """Per-scan new / unresolved / fixed / unverified counts for one comparable target.

    ``history`` must contain scans of the same comparable target. Only completed scans are used.
    """
    scans = sorted((r for r in history if r.state in COMPARABLE_STATES), key=lambda r: r.started_at)
    points = []
    previous = None
    for report in scans:
        comparison = compare(report, previous)
        points.append(
            {
                "scan_id": report.scan_id,
                "date": report.started_at.isoformat(),
                "label": report.started_at.strftime("%d %b %Y %H:%M"),
                "total": report.summary.findings_total,
                "high_priority": report.summary.severity_counts.high_priority,
                **comparison.counts(),
                "baseline": previous is None,
            }
        )
        previous = report
    return {"points": points, "enough_data": len(points) >= 2}


def prioritized_actions(report: ScanReport, limit: int = 6) -> list[dict]:
    """Rank actions by severity, then confirmed-before-potential, then confidence."""
    confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    ranked = sorted(
        report.findings,
        key=lambda f: (f.severity.rank, f.status != CheckStatus.FINDING, confidence_rank[f.confidence.value]),
    )
    actions = []
    for finding in ranked:
        if finding.severity.value == "INFO" and len(actions) >= 3:
            break
        actions.append(
            {
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "severity_label": finding.severity.label,
                "confidence": finding.confidence.value,
                "status": finding.status.value,
                "action": finding.recommendation,
                "why": finding.business_impact,
            }
        )
        if len(actions) >= limit:
            break
    return actions


def executive_summary(report: ScanReport) -> str:
    """Plain-English summary generated only from the report's actual contents."""
    s = report.summary
    host = report.hostname
    if report.state == ScanState.FAILED:
        return (
            f"WHITE could not complete an assessment of {host} because the website could not "
            "be reached safely. No conclusions about its security can be drawn from this scan."
        )
    if report.state == ScanState.CANCELLED:
        return (
            f"The scan of {host} was cancelled before all checks ran. Results below cover only "
            "the checks that completed."
        )
    executed = s.checks_total - s.status_counts.get("NOT_TESTED", 0)
    parts = [f"WHITE ran {executed} of {s.checks_total} checks against {host}."]
    if s.findings_total == 0:
        parts.append(
            "No issues were detected by these checks. This does not mean the website is "
            "secure; it means these specific problems were not observed."
        )
    else:
        sev = s.severity_counts
        bits = [
            f"{n} {label.lower()}"
            for n, label in (
                (sev.CRITICAL, "Critical"),
                (sev.HIGH, "High"),
                (sev.MEDIUM, "Medium"),
                (sev.LOW, "Low"),
                (sev.INFO, "Informational"),
            )
            if n
        ]
        parts.append(f"It recorded {s.findings_total} observation(s): {', '.join(bits)}.")
        if sev.high_priority:
            parts.append(f"{sev.high_priority} high-priority issue(s) should be addressed first.")
        elif sev.MEDIUM:
            parts.append(
                "There are no critical or high-severity observations; the medium-severity "
                "items are the most important to address."
            )
        else:
            parts.append("The observations are low-severity hardening improvements.")
        if s.potential_findings:
            parts.append(
                f"{s.potential_findings} of these are possible issues that need manual confirmation."
            )
    errors = s.status_counts.get("ERROR", 0)
    if errors:
        parts.append(f"{errors} check(s) could not run because of errors, so coverage is incomplete.")
    return " ".join(parts)


def overall_assessment(report: ScanReport) -> tuple[str, str]:
    """A short label and tone ('critical' | 'attention' | 'fair' | 'clear' | 'incomplete').

    Deliberately never says 'secure'.
    """
    if report.state in {ScanState.FAILED, ScanState.CANCELLED, ScanState.INTERRUPTED}:
        return "Assessment incomplete", "incomplete"
    sev = report.summary.severity_counts
    if sev.CRITICAL:
        return "Urgent action recommended", "critical"
    if sev.HIGH:
        return "Important issues found", "critical"
    if sev.MEDIUM:
        return "Improvements recommended", "attention"
    if sev.LOW or sev.INFO:
        return "Minor improvements suggested", "fair"
    return "No issues detected by these checks", "clear"

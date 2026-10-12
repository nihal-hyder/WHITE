"""Shared, versioned finding schema used by the scanner, CLI, API, GUI and reports."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


def utcnow() -> datetime:
    return datetime.now(UTC)


class CheckStatus(StrEnum):
    """Outcome of one check.

    PASS            The check completed and did not detect the issue it looks for.
                    It does NOT mean the website is secure.
    FINDING         The check detected the issue with direct supporting evidence.
    POTENTIAL       The check observed an indicator that needs manual confirmation.
    INCONCLUSIVE    The check ran but the evidence was insufficient to decide.
    NOT_APPLICABLE  The check does not apply to this target (e.g. no cookies were set).
    NOT_TESTED      The check was skipped (disabled, prerequisite missing, time limit).
    ERROR           The check could not run because of an execution error.
    """

    PASS = "PASS"
    FINDING = "FINDING"
    POTENTIAL = "POTENTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"


STATUS_LABELS = {
    CheckStatus.PASS: "Passed",
    CheckStatus.FINDING: "Issue found",
    CheckStatus.POTENTIAL: "Possible issue",
    CheckStatus.INCONCLUSIVE: "Inconclusive",
    CheckStatus.NOT_APPLICABLE: "Not applicable",
    CheckStatus.NOT_TESTED: "Skipped",
    CheckStatus.ERROR: "Error",
}


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    @property
    def label(self) -> str:
        return "Informational" if self is Severity.INFO else self.value.title()


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Confidence(StrEnum):
    """How certain WHITE is that the observation is accurate (independent of severity)."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(StrEnum):
    CONNECTION = "connection_security"
    BROWSER = "browser_security"
    COOKIES = "cookies"
    INFORMATION = "information_exposure"
    CONFIGURATION = "website_configuration"
    INPUT = "input_handling"

    @property
    def label(self) -> str:
        return CATEGORY_LABELS[self]


CATEGORY_LABELS = {
    Category.CONNECTION: "Connection protection",
    Category.BROWSER: "Browser security",
    Category.COOKIES: "Cookies",
    Category.INFORMATION: "Information exposure",
    Category.CONFIGURATION: "Website configuration",
    Category.INPUT: "Input handling",
}


class Evidence(BaseModel):
    label: str
    value: str


class Reference(BaseModel):
    title: str
    url: str


class Finding(BaseModel):
    """A single observation produced by a check (status FINDING or POTENTIAL)."""

    id: str = Field(description="Stable fingerprint of this issue for this target.")
    check_id: str
    check_version: str
    title: str
    category: Category
    status: CheckStatus
    severity: Severity
    confidence: Confidence
    summary: str = Field(description="Plain-English explanation of what was observed.")
    business_impact: str = Field(description="Why it matters, in business terms.")
    recommendation: str = Field(description="Practical next step in plain English.")
    technical_details: str
    technical_remediation: str
    evidence: list[Evidence] = Field(default_factory=list)
    affected_url: str | None = None
    references: list[Reference] = Field(default_factory=list)
    owasp: str | None = Field(default=None, description="OWASP Top 10:2025 taxonomy reference.")
    timestamp: datetime = Field(default_factory=utcnow)

    @staticmethod
    def fingerprint(check_id: str, key: str, host: str) -> str:
        digest = hashlib.sha256(f"{check_id}|{key}|{host.lower()}".encode()).hexdigest()
        return f"{check_id}:{digest[:16]}"


class CheckResult(BaseModel):
    check_id: str
    check_version: str
    name: str
    category: Category
    description: str
    status: CheckStatus
    message: str = Field(description="Short explanation of the outcome.")
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    duration_ms: int = 0


class ScanState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


FINISHED_STATES = {
    ScanState.COMPLETED,
    ScanState.COMPLETED_WITH_ERRORS,
    ScanState.FAILED,
    ScanState.CANCELLED,
    ScanState.INTERRUPTED,
}


class SeverityCounts(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0

    @property
    def total(self) -> int:
        return self.CRITICAL + self.HIGH + self.MEDIUM + self.LOW + self.INFO

    @property
    def high_priority(self) -> int:
        return self.CRITICAL + self.HIGH


class ScanSummary(BaseModel):
    checks_total: int = 0
    status_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)
    findings_total: int = 0
    confirmed_findings: int = 0
    potential_findings: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Safety limits for one scan. Defaults are conservative."""

    allow_private_targets: bool = False
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])
    request_timeout: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 2_000_000
    max_requests: int = 40
    max_scan_seconds: float = 120.0
    min_request_interval: float = 0.2
    active_checks: bool = False
    user_agent: str = "WHITE-Security-Scanner/1.0 (+authorized assessment)"


LIMITATIONS = [
    "WHITE performs a limited, non-intrusive, URL-based assessment. It cannot detect every "
    "vulnerability and does not guarantee that a website is secure.",
    "Only publicly reachable responses were inspected. Pages behind login, server "
    "configuration, source code, databases and third-party services were not examined.",
    "A 'Passed' check means only that the specific issue was not detected during this scan.",
    "Results reflect the website at the time of the scan; later changes are not covered.",
    "Potential findings are indicators that should be confirmed manually by a qualified person.",
    "WHITE does not attempt exploitation, password guessing, denial-of-service testing or form submission.",
]


class ScanReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    tool: str = "WHITE"
    tool_version: str
    scan_id: str
    target_url: str
    final_url: str | None = None
    hostname: str
    state: ScanState
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    active_checks_enabled: bool = False
    checks: list[CheckResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))
    summary: ScanSummary = Field(default_factory=ScanSummary)

    @property
    def findings(self) -> list[Finding]:
        items = [f for c in self.checks for f in c.findings]
        return sorted(items, key=lambda f: (f.severity.rank, f.status != CheckStatus.FINDING, f.title))

    def compute_summary(self) -> ScanSummary:
        status_counts = {s.value: 0 for s in CheckStatus}
        for check in self.checks:
            status_counts[check.status.value] += 1
        severity = SeverityCounts()
        categories: dict[str, int] = {c.value: 0 for c in Category}
        findings = self.findings
        for finding in findings:
            setattr(severity, finding.severity.value, getattr(severity, finding.severity.value) + 1)
            categories[finding.category.value] += 1
        self.summary = ScanSummary(
            checks_total=len(self.checks),
            status_counts=status_counts,
            severity_counts=severity,
            findings_total=len(findings),
            confirmed_findings=sum(1 for f in findings if f.status == CheckStatus.FINDING),
            potential_findings=sum(1 for f in findings if f.status == CheckStatus.POTENTIAL),
            category_counts=categories,
        )
        return self.summary

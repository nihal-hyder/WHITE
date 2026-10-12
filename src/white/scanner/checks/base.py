"""Base classes shared by all checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from bs4 import BeautifulSoup

from white.scanner.http import FetchResult, SafeHttpClient
from white.scanner.models import (
    Category,
    CheckResult,
    CheckStatus,
    Confidence,
    Evidence,
    Finding,
    Reference,
    ScanConfig,
    Severity,
)
from white.scanner.netsafety import ValidatedTarget
from white.scanner.redact import redact_text, redact_url


@dataclass
class ScanContext:
    target: ValidatedTarget
    client: SafeHttpClient
    config: ScanConfig
    _soup: BeautifulSoup | None = field(default=None, init=False)
    _soup_parsed: bool = field(default=False, init=False)

    @property
    def path(self) -> str:
        url = self.target.url
        rest = url.split("://", 1)[1]
        slash = rest.find("/")
        return rest[slash:] if slash >= 0 else "/"

    def url_for(self, scheme: str, path: str | None = None) -> str:
        host = f"[{self.target.host}]" if ":" in self.target.host else self.target.host
        port = self.target.port
        default = 443 if scheme == "https" else 80
        # Only keep a custom port for the scheme the user actually asked for.
        keep_port = scheme == self.target.scheme and port != default
        netloc = f"{host}:{port}" if keep_port else host
        return f"{scheme}://{netloc}{path if path is not None else self.path}"

    @property
    def https_url(self) -> str:
        return self.url_for("https")

    @property
    def http_url(self) -> str:
        return self.url_for("http")

    def fetch_https(self) -> FetchResult:
        return self.client.fetch(self.https_url)

    def fetch_http(self) -> FetchResult:
        return self.client.fetch(self.http_url)

    def primary(self) -> FetchResult:
        """The main page, preferring HTTPS. Falls back to the requested URL's scheme."""
        if self.target.scheme == "https":
            return self.fetch_https()
        https = self.fetch_https()
        return https if https.ok else self.fetch_http()

    def origin_url(self, path: str) -> str:
        primary = self.primary()
        base = primary.final_url if primary.ok and primary.final_url else self.target.url
        scheme, rest = base.split("://", 1)
        netloc = rest.split("/", 1)[0]
        return f"{scheme}://{netloc}{path}"

    def soup(self) -> BeautifulSoup | None:
        if not self._soup_parsed:
            self._soup_parsed = True
            primary = self.primary()
            if primary.ok and primary.is_html and primary.body:
                self._soup = BeautifulSoup(primary.text, "html.parser")
        return self._soup


@dataclass
class Outcome:
    status: CheckStatus
    message: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Check:
    id: ClassVar[str]
    version: ClassVar[str] = "1.0"
    name: ClassVar[str]
    category: ClassVar[Category]
    description: ClassVar[str]
    owasp: ClassVar[str | None] = None
    active: ClassVar[bool] = False  # active checks send crafted (harmless) input; opt-in only
    references: ClassVar[list[tuple[str, str]]] = []

    def evaluate(self, ctx: ScanContext) -> Outcome:  # pragma: no cover - abstract
        raise NotImplementedError

    def result(self, outcome: Outcome) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            check_version=self.version,
            name=self.name,
            category=self.category,
            description=self.description,
            status=outcome.status,
            message=outcome.message,
            findings=outcome.findings,
            errors=outcome.errors,
        )

    def finding(
        self,
        ctx: ScanContext,
        *,
        key: str,
        title: str,
        severity: Severity,
        confidence: Confidence,
        summary: str,
        impact: str,
        recommendation: str,
        technical: str,
        technical_remediation: str,
        evidence: list[tuple[str, str]],
        affected_url: str | None = None,
        status: CheckStatus = CheckStatus.FINDING,
        category: Category | None = None,
    ) -> Finding:
        return Finding(
            id=Finding.fingerprint(self.id, key, ctx.target.host),
            check_id=self.id,
            check_version=self.version,
            title=title,
            category=category or self.category,
            status=status,
            severity=severity,
            confidence=confidence,
            summary=summary,
            business_impact=impact,
            recommendation=recommendation,
            technical_details=technical,
            technical_remediation=technical_remediation,
            evidence=[Evidence(label=k, value=redact_text(v)) for k, v in evidence],
            affected_url=redact_url(affected_url),
            references=[Reference(title=t, url=u) for t, u in self.references],
            owasp=self.owasp,
        )


def unreachable(primary: FetchResult) -> Outcome:
    return Outcome(
        CheckStatus.ERROR,
        "The website could not be reached, so this check could not run.",
        errors=[primary.error or "No response received."],
    )

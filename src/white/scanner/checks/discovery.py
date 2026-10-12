"""robots.txt, sitemap.xml and a small, documented set of public-file exposure checks."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from white.scanner.checks.base import Check, Outcome, ScanContext, unreachable
from white.scanner.http import FetchResult
from white.scanner.models import Category, CheckStatus, Confidence, Severity

SENSITIVE_PATH = re.compile(
    r"(admin|backup|bak|private|secret|config|internal|staging|test|dev|\.git|\.env|db|database|"
    r"dump|old|tmp|debug|phpmyadmin)",
    re.I,
)


def _is_text_file(response: FetchResult) -> bool:
    """A real robots/sitemap file - not an HTML 'soft 404' page returned for every path."""
    if not response.ok or response.status_code != 200 or not response.body:
        return False
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        return False
    return not response.text.lstrip().lower().startswith(("<!doctype html", "<html"))


class RobotsTxtCheck(Check):
    id = "robots-txt"
    name = "robots.txt review"
    category = Category.INFORMATION
    description = "Reads robots.txt and notes entries that point to potentially sensitive areas."
    owasp = "A02:2025 Security Misconfiguration"

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        url = ctx.origin_url("/robots.txt")
        response = ctx.client.fetch(url)
        if not response.ok:
            return Outcome(
                CheckStatus.ERROR, "robots.txt could not be retrieved.", errors=[response.error or ""]
            )
        if not _is_text_file(response):
            return Outcome(
                CheckStatus.NOT_APPLICABLE,
                f"No robots.txt file is published (status {response.status_code}).",
            )
        disallow, sitemaps = [], []
        for line in response.text.splitlines()[:2000]:
            key, _, value = line.split("#", 1)[0].partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "disallow" and value:
                disallow.append(value)
            elif key == "sitemap" and value:
                sitemaps.append(value)
        sensitive = [p for p in disallow if SENSITIVE_PATH.search(p)]
        message = f"robots.txt found: {len(disallow)} Disallow rule(s), {len(sitemaps)} sitemap reference(s)."
        if sensitive:
            f = self.finding(
                ctx,
                key="robots-sensitive",
                title="robots.txt points to potentially sensitive areas",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                status=CheckStatus.POTENTIAL,
                summary="The public robots.txt file lists paths whose names suggest administrative, "
                "backup or internal areas.",
                impact="robots.txt is public and is not a security control. Listing sensitive paths "
                "tells anyone where to look. This is only a concern if those areas are reachable "
                "without proper protection.",
                recommendation="Make sure the listed areas require login or are not publicly "
                "reachable, rather than relying on robots.txt to hide them.",
                technical=message,
                technical_remediation="Protect sensitive paths with authentication/authorization; "
                "avoid naming them in robots.txt.",
                evidence=[("Disallow", p) for p in sensitive[:10]],
                affected_url=url,
            )
            return Outcome(CheckStatus.POTENTIAL, message, [f])
        return Outcome(CheckStatus.PASS, message)


class SitemapCheck(Check):
    id = "sitemap-xml"
    name = "sitemap.xml review"
    category = Category.INFORMATION
    description = "Reads sitemap.xml (without following nested sitemaps) and notes sensitive-looking URLs."
    owasp = "A02:2025 Security Misconfiguration"

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        url = ctx.origin_url("/sitemap.xml")
        response = ctx.client.fetch(url)
        if not response.ok:
            return Outcome(
                CheckStatus.ERROR, "sitemap.xml could not be retrieved.", errors=[response.error or ""]
            )
        text = response.text if _is_text_file(response) else ""
        if "<urlset" not in text and "<sitemapindex" not in text:
            return Outcome(
                CheckStatus.NOT_APPLICABLE,
                f"No sitemap.xml file is published (status {response.status_code}).",
            )
        # Regex extraction avoids XML entity expansion risks from untrusted XML.
        locations = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)[:5000]
        kind = "sitemap index" if "<sitemapindex" in text else "sitemap"
        message = f"{kind} found with {len(locations)} URL(s){' (truncated)' if response.truncated else ''}."
        sensitive = [loc for loc in locations if SENSITIVE_PATH.search(urlsplit(loc).path)]
        if sensitive:
            f = self.finding(
                ctx,
                key="sitemap-sensitive",
                title="sitemap.xml lists potentially sensitive pages",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                status=CheckStatus.POTENTIAL,
                summary="The public sitemap includes addresses whose names suggest administrative, "
                "test or internal pages.",
                impact="Search engines may index these pages. Confirm they are meant to be public.",
                recommendation="Review the listed pages and remove any that should not be public.",
                technical=message,
                technical_remediation="Exclude non-public pages from sitemap generation and protect them.",
                evidence=[("URL", loc) for loc in sensitive[:10]],
                affected_url=url,
            )
            return Outcome(CheckStatus.POTENTIAL, message, [f])
        return Outcome(CheckStatus.PASS, message)


def _env_names(text: str) -> list[str]:
    names = []
    for line in text.splitlines()[:500]:
        match = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=", line)
        if match:
            names.append(match.group(1))
    return names


PUBLIC_FILES = [
    # (path, label, severity, detector, description)
    (
        "/.git/HEAD",
        "Git repository metadata",
        Severity.HIGH,
        lambda r: bool(re.match(r"^(ref: refs/|[0-9a-f]{40}\s*$)", r.text.strip())),
    ),
    (
        "/.env",
        "Environment configuration file (.env)",
        Severity.HIGH,
        lambda r: len(_env_names(r.text)) >= 2 and "<html" not in r.text.lower(),
    ),
    (
        "/.DS_Store",
        "macOS folder metadata (.DS_Store)",
        Severity.LOW,
        lambda r: r.body[:8] == b"\x00\x00\x00\x01Bud1",
    ),
    (
        "/server-status",
        "Apache server status page",
        Severity.MEDIUM,
        lambda r: "Apache Server Status" in r.text,
    ),
    (
        "/phpinfo.php",
        "PHP configuration page (phpinfo)",
        Severity.MEDIUM,
        lambda r: "phpinfo()" in r.text and "PHP Version" in r.text,
    ),
]


class PublicFileExposureCheck(Check):
    id = "public-file-exposure"
    name = "Sensitive file exposure"
    category = Category.INFORMATION
    description = (
        "Requests a small fixed list of well-known sensitive files (/.git/HEAD, /.env, "
        "/.DS_Store, /server-status, /phpinfo.php) and confirms exposure by content."
    )
    owasp = "A02:2025 Security Misconfiguration"

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        findings, errors = [], []
        for path, label, severity, detector in PUBLIC_FILES:
            url = ctx.origin_url(path)
            response = ctx.client.fetch(url, follow_redirects=False)
            if not response.ok:
                errors.append(f"{path}: {response.error}")
                continue
            if response.status_code != 200 or not response.body or not detector(response):
                continue
            evidence = [("URL", url), ("Status", "200"), ("Content verified", "yes")]
            sev = severity
            if path == "/.env":
                names = _env_names(response.text)
                evidence.append(("Variable names (values not stored)", ", ".join(names[:15])))
                if any(re.search(r"PASS|SECRET|KEY|TOKEN", n) for n in names):
                    sev = Severity.CRITICAL
            findings.append(
                self.finding(
                    ctx,
                    key=f"file:{path}",
                    title=f"{label} is publicly accessible",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    summary=f"Anyone can download {path} from the website. This file is not meant to be public.",
                    impact="Files like this can reveal passwords, keys, source code or internal "
                    "configuration that attackers can use directly.",
                    recommendation="Ask your web team to block access to this file immediately and, if "
                    "it contained passwords or keys, change them.",
                    technical=f"GET {url} returned 200 and the content matched the expected format of {label}.",
                    technical_remediation="Remove the file from the web root or deny access in the web "
                    "server configuration; rotate any exposed credentials.",
                    evidence=evidence,
                    affected_url=url,
                )
            )
        if findings:
            return Outcome(
                CheckStatus.FINDING, f"{len(findings)} sensitive file(s) exposed.", findings, errors
            )
        if len(errors) == len(PUBLIC_FILES):
            return Outcome(CheckStatus.ERROR, "None of the files could be requested.", errors=errors)
        return Outcome(
            CheckStatus.PASS,
            f"None of the {len(PUBLIC_FILES)} known sensitive files were exposed.",
            errors=errors,
        )

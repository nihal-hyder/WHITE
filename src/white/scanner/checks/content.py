"""Checks that inspect page content: mixed content, forms, error disclosure, directory listing.

WHITE never submits forms or executes downloaded content; HTML is only parsed.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlsplit

from bs4 import Comment

from white.scanner.checks.base import Check, Outcome, ScanContext, unreachable
from white.scanner.models import Category, CheckStatus, Confidence, Severity

OWASP_MISCONFIG = "A02:2025 Security Misconfiguration"

ACTIVE_TAGS = {"script": "src", "iframe": "src", "object": "data", "embed": "src", "frame": "src"}
PASSIVE_TAGS = {"img": "src", "audio": "src", "video": "src", "source": "src", "track": "src"}


class MixedContentCheck(Check):
    id = "mixed-content"
    name = "Mixed content"
    category = Category.CONNECTION
    description = "Looks for resources loaded over HTTP on a page served over HTTPS."
    owasp = "A04:2025 Cryptographic Failures"
    references = [
        ("MDN: Mixed content", "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content")
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        if not (primary.final_url or "").startswith("https://"):
            return Outcome(CheckStatus.NOT_APPLICABLE, "Mixed content only applies to HTTPS pages.")
        soup = ctx.soup()
        if soup is None:
            return Outcome(CheckStatus.NOT_APPLICABLE, "The main response was not an HTML page.")
        active, passive = [], []
        for tag, attr in ACTIVE_TAGS.items():
            for el in soup.find_all(tag):
                value = (el.get(attr) or "").strip()
                if value.lower().startswith("http://"):
                    active.append(f"<{tag}> {value}")
        for el in soup.find_all("link"):
            rel = " ".join(el.get("rel") or []).lower()
            href = (el.get("href") or "").strip()
            if "stylesheet" in rel and href.lower().startswith("http://"):
                active.append(f"<link stylesheet> {href}")
        for tag, attr in PASSIVE_TAGS.items():
            for el in soup.find_all(tag):
                value = (el.get(attr) or "").strip()
                if value.lower().startswith("http://"):
                    passive.append(f"<{tag}> {value}")
        url = primary.final_url
        findings = []
        if active:
            findings.append(
                self.finding(
                    ctx,
                    key="mixed-active",
                    title="Secure page loads scripts or styles over HTTP",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary=f"The HTTPS page references {len(active)} script, frame or style resource(s) "
                    "over unencrypted HTTP.",
                    impact="Browsers usually block these resources, which can break the page. Where they "
                    "load, an attacker on the network could replace them and take control of the page.",
                    recommendation="Ask your web team to load every resource over https://.",
                    technical="Active mixed content references found in the HTML.",
                    technical_remediation="Change resource URLs to https:// (or relative URLs) and "
                    "consider `Content-Security-Policy: upgrade-insecure-requests`.",
                    evidence=[("Resource", r) for r in active[:10]],
                    affected_url=url,
                )
            )
        if passive:
            findings.append(
                self.finding(
                    ctx,
                    key="mixed-passive",
                    title="Secure page loads images or media over HTTP",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=f"The HTTPS page references {len(passive)} image or media file(s) over HTTP.",
                    impact="Browsers may show the page as not fully secure, and the media could be "
                    "swapped by someone on the network.",
                    recommendation="Load images and media over https://.",
                    technical="Passive mixed content references found in the HTML.",
                    technical_remediation="Change media URLs to https:// or relative URLs.",
                    evidence=[("Resource", r) for r in passive[:10]],
                    affected_url=url,
                )
            )
        if findings:
            return Outcome(CheckStatus.FINDING, "Mixed content references found.", findings)
        return Outcome(CheckStatus.PASS, "No HTTP resource references found on the main page.")


class FormSecurityCheck(Check):
    id = "form-security"
    name = "Form security"
    category = Category.CONFIGURATION
    description = (
        "Inspects forms on the main page for insecure submission targets. Forms are never submitted."
    )
    owasp = "A04:2025 Cryptographic Failures"

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        soup = ctx.soup()
        if soup is None:
            return Outcome(CheckStatus.NOT_APPLICABLE, "The main response was not an HTML page.")
        forms = soup.find_all("form")
        if not forms:
            return Outcome(CheckStatus.NOT_APPLICABLE, "No forms were found on the main page.")
        page_url = primary.final_url or ctx.target.url
        insecure_action, password_get = [], []
        page_password_http = False
        for form in forms:
            action = urljoin(page_url, (form.get("action") or "").strip() or page_url)
            method = (form.get("method") or "get").strip().lower()
            has_password = form.find("input", attrs={"type": re.compile("^password$", re.I)}) is not None
            if action.lower().startswith("http://"):
                insecure_action.append((action, has_password))
            if has_password and method == "get":
                password_get.append(action)
            if has_password and page_url.startswith("http://"):
                page_password_http = True
        findings = []
        if insecure_action or page_password_http:
            with_password = page_password_http or any(p for _, p in insecure_action)
            evidence = [
                ("Form action", a + (" (contains password field)" if p else ""))
                for a, p in insecure_action[:8]
            ]
            if page_password_http:
                evidence.append(("Page", f"{page_url} contains a password field and is served over HTTP"))
            findings.append(
                self.finding(
                    ctx,
                    key="form-insecure-action",
                    title="Form sends information over an unencrypted connection",
                    severity=Severity.HIGH if with_password else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary="At least one form on the page submits what visitors type over plain HTTP.",
                    impact="Anything entered into the form, potentially including passwords or personal "
                    "details, could be read by others on the same network.",
                    recommendation="Ask your web team to make every form submit to an https:// address "
                    "and serve the page itself over HTTPS.",
                    technical="Form actions resolve to http:// URLs or a password field is served over HTTP.",
                    technical_remediation="Use https:// form actions and serve pages over HTTPS only.",
                    evidence=evidence,
                    affected_url=page_url,
                )
            )
        if password_get:
            findings.append(
                self.finding(
                    ctx,
                    key="form-password-get",
                    title="Password form uses the GET method",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary="A form containing a password field sends its data in the page address.",
                    impact="Passwords placed in addresses can end up in browser history, server logs "
                    "and analytics tools.",
                    recommendation="Ask your web team to change the form to use POST.",
                    technical="Form with input[type=password] has method=GET.",
                    technical_remediation='Use method="post" for forms with credentials.',
                    evidence=[("Form action", a) for a in password_get[:8]],
                    affected_url=page_url,
                )
            )
        if findings:
            return Outcome(CheckStatus.FINDING, f"{len(forms)} form(s) inspected; issues found.", findings)
        return Outcome(CheckStatus.PASS, f"{len(forms)} form(s) inspected; all submit over HTTPS.")


ERROR_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    (
        "Django debug page",
        re.compile(r"You're seeing this error because you have\s+<code>DEBUG = True", re.I),
    ),
    ("Laravel/Whoops debug page", re.compile(r"Whoops(!| -) There was an error|Ignition", re.I)),
    (
        "ASP.NET error page",
        re.compile(
            r"Server Error in '.*' Application|Version Information:\s*Microsoft \.NET Framework", re.I
        ),
    ),
    (
        "PHP error message",
        re.compile(r"<b>(Fatal error|Parse error|Warning)</b>:.+ on line <b>\d+</b>", re.I),
    ),
    (
        "Java stack trace",
        re.compile(r"\bat (java|javax|org\.springframework|org\.apache)\.[\w.$]+\([\w]+\.java:\d+\)"),
    ),
    ("Ruby on Rails error page", re.compile(r"Action Controller: Exception caught", re.I)),
    ("Node.js stack trace", re.compile(r"at [\w.<>]+ \((/[^)]+|[A-Z]:\\[^)]+)\.js:\d+:\d+\)")),
    (
        "Database error message",
        re.compile(r"SQLSTATE\[\w+\]|ORA-\d{5}|You have an error in your SQL syntax", re.I),
    ),
]
SECRET_COMMENT = re.compile(
    r"(password|passwd|api[_-]?key|secret|private[_ -]key|access[_-]?token)\s*[:=]", re.I
)


class InformationDisclosureCheck(Check):
    id = "information-disclosure"
    name = "Error and debug information disclosure"
    category = Category.INFORMATION
    description = (
        "Looks for stack traces, debug pages and credential-like HTML comments on the main "
        "page and on a 'page not found' response."
    )
    owasp = "A10:2025 Mishandling of Exceptional Conditions"

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        probe_url = ctx.origin_url(f"/white-check-{secrets.token_hex(6)}")
        missing = ctx.client.fetch(probe_url, follow_redirects=False)
        findings = []
        for label, response in (("Main page", primary), ("Not-found page", missing)):
            if not response.ok or not response.body:
                continue
            text = response.text
            for name, pattern in ERROR_SIGNATURES:
                match = pattern.search(text)
                if not match:
                    continue
                start = max(match.start() - 60, 0)
                snippet = re.sub(r"<[^>]+>", " ", text[start : match.end() + 120])
                findings.append(
                    self.finding(
                        ctx,
                        key=f"error:{name}",
                        title=f"Technical error details are shown to visitors ({name})",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        summary="The website displays internal error details that are meant only for developers.",
                        impact="Error details can reveal file locations, software versions and code "
                        "structure, which makes attacks easier. Debug pages sometimes expose "
                        "configuration secrets.",
                        recommendation="Ask your web team to turn off debug mode and show a generic "
                        "error page instead.",
                        technical=f"{label} ({response.final_url}, status {response.status_code}) "
                        f"matched the '{name}' signature.",
                        technical_remediation="Disable debug/development mode in production, configure "
                        "custom error pages and log details server-side only.",
                        evidence=[
                            ("URL", response.final_url or ""),
                            ("Status", str(response.status_code)),
                            ("Excerpt", snippet),
                        ],
                        affected_url=response.final_url,
                    )
                )
                break
        soup = ctx.soup()
        if soup is not None:
            comments = [
                c for c in soup.find_all(string=lambda s: isinstance(s, Comment)) if SECRET_COMMENT.search(c)
            ]
            if comments:
                findings.append(
                    self.finding(
                        ctx,
                        key="secret-like-comment",
                        title="HTML comments mention credentials",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        status=CheckStatus.POTENTIAL,
                        summary="The page source contains developer comments that mention passwords, keys or tokens.",
                        impact="Comments are visible to anyone who views the page source. If they contain "
                        "real credentials, those could be misused. This needs manual review; the values "
                        "are not shown in this report.",
                        recommendation="Ask your web team to review and remove these comments.",
                        technical=f"{len(comments)} HTML comment(s) matched a credential keyword pattern.",
                        technical_remediation="Strip comments from production HTML and rotate any "
                        "credential that was exposed.",
                        evidence=[("Comment (redacted)", str(c)) for c in comments[:3]],
                        affected_url=primary.final_url,
                    )
                )
        if findings:
            status = (
                CheckStatus.FINDING
                if any(f.status == CheckStatus.FINDING for f in findings)
                else CheckStatus.POTENTIAL
            )
            return Outcome(status, "Possible information disclosure observed.", findings)
        errors = [] if missing.ok else [f"Not-found probe: {missing.error}"]
        return Outcome(
            CheckStatus.PASS, "No debug pages, stack traces or credential-like comments found.", errors=errors
        )


LISTING = re.compile(r"<title>\s*(Index of /|Directory listing for /)|<h1>\s*Index of /", re.I)


class DirectoryListingCheck(Check):
    id = "directory-listing"
    name = "Directory listing"
    category = Category.INFORMATION
    description = (
        "Checks whether the main page, and up to three folders referenced by it, "
        "show automatic file listings."
    )
    owasp = OWASP_MISCONFIG

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        candidates: list[str] = []
        base = primary.final_url or ctx.target.url
        base_host = urlsplit(base).hostname
        soup = ctx.soup()
        if soup is not None:
            for el in soup.find_all(["script", "img", "link"]):
                ref = el.get("src") or el.get("href")
                if not ref:
                    continue
                absolute = urljoin(base, ref.strip())
                parts = urlsplit(absolute)
                if parts.hostname != base_host or parts.scheme not in {"http", "https"}:
                    continue
                folder = parts.path.rsplit("/", 1)[0] + "/"
                if folder != "/":
                    url = f"{parts.scheme}://{parts.netloc}{folder}"
                    if url not in candidates:
                        candidates.append(url)
                if len(candidates) >= 3:
                    break
        listings = []
        if primary.body and LISTING.search(primary.text):
            listings.append(primary.final_url or base)
        for url in candidates:
            response = ctx.client.fetch(url, follow_redirects=False)
            if response.ok and response.status_code == 200 and LISTING.search(response.text):
                listings.append(url)
        if listings:
            f = self.finding(
                ctx,
                key="directory-listing",
                title="Folder contents are publicly listed",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="The web server shows an automatic list of files in at least one folder.",
                impact="Anyone can browse files that were not meant to be linked publicly, such as "
                "backups, documents or configuration files.",
                recommendation="Ask your web team to disable directory listing on the web server.",
                technical="Response matched an auto-index page signature ('Index of /').",
                technical_remediation="Disable auto-indexing (`Options -Indexes` in Apache, "
                "`autoindex off` in nginx) and add index pages where needed.",
                evidence=[("Listing URL", u) for u in listings],
                affected_url=listings[0],
            )
            return Outcome(CheckStatus.FINDING, "Directory listing detected.", [f])
        return Outcome(
            CheckStatus.PASS,
            f"No directory listing on the main page or {len(candidates)} referenced folder(s).",
        )

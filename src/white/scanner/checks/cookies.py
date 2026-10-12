"""Cookie security attribute checks. Cookie values are never stored."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from white.scanner.checks.base import Check, Outcome, ScanContext, unreachable
from white.scanner.models import Category, CheckStatus, Confidence, Severity
from white.scanner.redact import redact_cookie

SESSION_NAME = re.compile(
    r"(sess|sid|auth|token|login|jwt|remember|phpsessid|jsessionid|asp\.net_sessionid|"
    r"connect\.sid|_session|identity|user)",
    re.I,
)


@dataclass
class ParsedCookie:
    name: str
    raw: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def session_like(self) -> bool:
        return bool(SESSION_NAME.search(self.name))


def parse_set_cookie(header: str) -> ParsedCookie | None:
    head, _, rest = header.partition(";")
    if "=" not in head:
        return None
    name = head.split("=", 1)[0].strip()
    if not name:
        return None
    cookie = ParsedCookie(name=name, raw=redact_cookie(header))
    for attribute in rest.split(";"):
        key, _, value = attribute.strip().partition("=")
        key_l = key.strip().lower()
        if not key_l:
            continue
        cookie.attributes[key_l] = value.strip()
        if key_l == "secure":
            cookie.secure = True
        elif key_l == "httponly":
            cookie.http_only = True
        elif key_l == "samesite":
            cookie.same_site = value.strip().lower() or None
    return cookie


class CookieSecurityCheck(Check):
    id = "cookie-security"
    name = "Cookie security attributes"
    category = Category.COOKIES
    description = "Checks cookies for the Secure, HttpOnly and SameSite protections."
    owasp = "A07:2025 Authentication Failures"
    references = [
        ("MDN: Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"),
        (
            "OWASP Session Management Cheat Sheet",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ),
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        cookies: dict[str, ParsedCookie] = {}
        for hop in primary.hops:
            for header in hop.headers.get_list("set-cookie"):
                parsed = parse_set_cookie(header)
                if parsed:
                    cookies[parsed.name] = parsed
        if not cookies:
            return Outcome(CheckStatus.NOT_APPLICABLE, "The main page did not set any cookies.")
        https_site = (primary.final_url or "").startswith("https://")
        url = primary.final_url
        findings = []

        no_secure = [c for c in cookies.values() if not c.secure] if https_site else []
        if no_secure:
            sev = Severity.MEDIUM if any(c.session_like for c in no_secure) else Severity.LOW
            findings.append(
                self.finding(
                    ctx,
                    key="cookie-no-secure",
                    title="Cookies can be sent over unencrypted connections",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    summary=f"{len(no_secure)} cookie(s) are missing the Secure flag, so browsers may "
                    "send them over plain HTTP.",
                    impact="If a cookie identifies a logged-in user, someone on the same network could "
                    "capture it and impersonate that user.",
                    recommendation="Ask your web team to mark all cookies as Secure.",
                    technical="Cookies without Secure: " + ", ".join(c.name for c in no_secure),
                    technical_remediation="Add the `Secure` attribute to every Set-Cookie header on HTTPS sites.",
                    evidence=[("Set-Cookie", c.raw) for c in no_secure[:8]],
                    affected_url=url,
                )
            )
        no_httponly = [c for c in cookies.values() if not c.http_only]
        if no_httponly:
            session = [c for c in no_httponly if c.session_like]
            findings.append(
                self.finding(
                    ctx,
                    key="cookie-no-httponly",
                    title="Cookies are readable by page scripts (no HttpOnly)",
                    severity=Severity.MEDIUM if session else Severity.LOW,
                    confidence=Confidence.MEDIUM if session else Confidence.LOW,
                    summary=f"{len(no_httponly)} cookie(s) are missing the HttpOnly flag, so scripts "
                    "running on the page can read them.",
                    impact="If a session cookie is readable by scripts, an injected script could steal "
                    "it. Some cookies (for example preference or analytics cookies) are intentionally "
                    "readable; WHITE cannot tell each cookie's purpose for certain.",
                    recommendation="Ask your web team to add HttpOnly to cookies that do not need to be "
                    "read by JavaScript, especially login/session cookies.",
                    technical="Cookies without HttpOnly: "
                    + ", ".join(c.name for c in no_httponly)
                    + (
                        f". Names suggesting a session: {', '.join(c.name for c in session)}"
                        if session
                        else ""
                    ),
                    technical_remediation="Add the `HttpOnly` attribute to session and authentication cookies.",
                    evidence=[("Set-Cookie", c.raw) for c in no_httponly[:8]],
                    affected_url=url,
                )
            )
        no_samesite = [c for c in cookies.values() if not c.same_site]
        none_insecure = [c for c in cookies.values() if c.same_site == "none" and not c.secure]
        if none_insecure:
            findings.append(
                self.finding(
                    ctx,
                    key="cookie-samesite-none-insecure",
                    title="Cookies use SameSite=None without Secure",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary="Some cookies allow cross-site use but are not marked Secure. Modern "
                    "browsers reject these cookies.",
                    impact="Features that depend on these cookies may break, and older browsers "
                    "send them insecurely.",
                    recommendation="Add the Secure flag to these cookies or change SameSite.",
                    technical="Cookies: " + ", ".join(c.name for c in none_insecure),
                    technical_remediation="Cookies with `SameSite=None` must also include `Secure`.",
                    evidence=[("Set-Cookie", c.raw) for c in none_insecure[:8]],
                    affected_url=url,
                )
            )
        if no_samesite:
            findings.append(
                self.finding(
                    ctx,
                    key="cookie-no-samesite",
                    title="Cookies do not declare a SameSite policy",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=f"{len(no_samesite)} cookie(s) do not say whether they may be sent with "
                    "requests from other websites.",
                    impact="Most modern browsers default to a safe setting (Lax), but older browsers "
                    "may send these cookies with cross-site requests, which can assist cross-site "
                    "request forgery.",
                    recommendation="Ask your web team to set SameSite=Lax (or Strict) explicitly.",
                    technical="Cookies without SameSite: " + ", ".join(c.name for c in no_samesite),
                    technical_remediation="Add `SameSite=Lax` or `SameSite=Strict` to Set-Cookie headers.",
                    evidence=[("Set-Cookie", c.raw) for c in no_samesite[:8]],
                    affected_url=url,
                )
            )
        if findings:
            return Outcome(
                CheckStatus.FINDING, f"{len(cookies)} cookie(s) inspected; issues found.", findings
            )
        return Outcome(
            CheckStatus.PASS, f"{len(cookies)} cookie(s) inspected; all use Secure, HttpOnly and SameSite."
        )

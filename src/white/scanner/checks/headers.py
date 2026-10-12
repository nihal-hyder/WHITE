"""Browser security header checks and server identification headers."""

from __future__ import annotations

import re

from white.scanner.checks.base import Check, Outcome, ScanContext, unreachable
from white.scanner.models import Category, CheckStatus, Confidence, Severity

OWASP_MISCONFIG = "A02:2025 Security Misconfiguration"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


def _primary_or_error(ctx: ScanContext):
    primary = ctx.primary()
    return primary, (None if primary.ok else unreachable(primary))


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), list(tokens[1:]))
    return directives


class ContentSecurityPolicyCheck(Check):
    id = "content-security-policy"
    name = "Content-Security-Policy"
    category = Category.BROWSER
    description = "Checks for a Content-Security-Policy that limits where scripts can load from."
    owasp = OWASP_MISCONFIG
    references = [
        ("MDN: Content-Security-Policy", MDN + "Content-Security-Policy"),
        (
            "OWASP CSP Cheat Sheet",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        ),
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary, error = _primary_or_error(ctx)
        if error:
            return error
        url = primary.final_url or ""
        value = primary.headers.get("content-security-policy")
        report_only = primary.headers.get("content-security-policy-report-only")
        if not value:
            title = (
                "Content-Security-Policy is only in report-only mode"
                if report_only
                else "Content-Security-Policy header is missing"
            )
            f = self.finding(
                ctx,
                key="csp-missing",
                title=title,
                severity=Severity.LOW if report_only else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="The website does not instruct browsers to restrict which scripts and "
                "content may run on its pages.",
                impact="If an attacker manages to inject code into a page (cross-site scripting), "
                "nothing limits what that code can do, such as stealing visitor data.",
                recommendation="Ask your web team to introduce a Content-Security-Policy, starting "
                "in report-only mode and then enforcing it.",
                technical="No enforcing Content-Security-Policy header on the main response."
                + (f" Report-only policy: {report_only}" if report_only else ""),
                technical_remediation="Define a policy such as `default-src 'self'; script-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'` and adjust to the "
                "site's legitimate sources. Prefer nonces or hashes over 'unsafe-inline'.",
                evidence=[("URL", url), ("Content-Security-Policy", "not present")]
                + ([("Report-Only", report_only)] if report_only else []),
                affected_url=url,
            )
            return Outcome(CheckStatus.FINDING, "No enforcing Content-Security-Policy.", [f])
        directives = parse_csp(value)
        script = directives.get("script-src", directives.get("default-src"))
        weaknesses = []
        if script is None:
            weaknesses.append("no script-src or default-src directive")
        else:
            lowered = [s.lower() for s in script]
            has_nonce_or_hash = any(
                s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered
            )
            if "'unsafe-inline'" in lowered and not has_nonce_or_hash and "'strict-dynamic'" not in lowered:
                weaknesses.append("script sources allow 'unsafe-inline'")
            if "*" in lowered or "http:" in lowered or "https:" in lowered or "data:" in lowered:
                weaknesses.append("script sources allow any host or scheme")
            if "'unsafe-eval'" in lowered:
                weaknesses.append("script sources allow 'unsafe-eval'")
        if weaknesses:
            f = self.finding(
                ctx,
                key="csp-weak",
                title="Content-Security-Policy allows unsafe script sources",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                summary="A Content-Security-Policy is present, but it still allows types of script "
                "that weaken its protection.",
                impact="The policy offers limited protection against injected scripts.",
                recommendation="Ask your web team to tighten the policy's script rules.",
                technical="Weaknesses: " + "; ".join(weaknesses) + f". Policy: {value}",
                technical_remediation="Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; "
                "use nonces or hashes with 'strict-dynamic'.",
                evidence=[("Content-Security-Policy", value), ("Weaknesses", "; ".join(weaknesses))],
                affected_url=url,
            )
            return Outcome(CheckStatus.FINDING, "Content-Security-Policy has weaknesses.", [f])
        return Outcome(CheckStatus.PASS, "An enforcing Content-Security-Policy is present.")


class ClickjackingCheck(Check):
    id = "clickjacking-protection"
    name = "Clickjacking protection"
    category = Category.BROWSER
    description = "Checks that other websites cannot embed this site in a hidden frame."
    owasp = OWASP_MISCONFIG
    references = [
        (
            "OWASP Clickjacking Defense",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        )
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary, error = _primary_or_error(ctx)
        if error:
            return error
        xfo = (primary.headers.get("x-frame-options") or "").strip()
        csp = primary.headers.get("content-security-policy") or ""
        frame_ancestors = parse_csp(csp).get("frame-ancestors")
        if frame_ancestors is not None:
            return Outcome(
                CheckStatus.PASS, f"CSP frame-ancestors is set ({' '.join(frame_ancestors) or 'empty'})."
            )
        if xfo.upper() in {"DENY", "SAMEORIGIN"}:
            return Outcome(CheckStatus.PASS, f"X-Frame-Options is set to {xfo.upper()}.")
        url = primary.final_url or ""
        f = self.finding(
            ctx,
            key="clickjacking",
            title="Website can be embedded by other sites (clickjacking)",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            summary="The website does not stop other websites from displaying it inside a frame.",
            impact="An attacker could display your site invisibly within their own page and trick "
            "visitors into clicking buttons they cannot see, such as confirming an action.",
            recommendation="Ask your web team to add frame protection (X-Frame-Options or a CSP "
            "frame-ancestors rule).",
            technical=f"X-Frame-Options: {xfo or 'not present'}; CSP frame-ancestors: not present.",
            technical_remediation="Send `Content-Security-Policy: frame-ancestors 'self'` (preferred) "
            "and/or `X-Frame-Options: SAMEORIGIN`.",
            evidence=[
                ("URL", url),
                ("X-Frame-Options", xfo or "not present"),
                ("CSP frame-ancestors", "not present"),
            ],
            affected_url=url,
        )
        return Outcome(CheckStatus.FINDING, "No clickjacking protection header.", [f])


class ContentTypeOptionsCheck(Check):
    id = "x-content-type-options"
    name = "X-Content-Type-Options"
    category = Category.BROWSER
    description = "Checks that browsers are told not to guess file types (nosniff)."
    owasp = OWASP_MISCONFIG
    references = [("MDN: X-Content-Type-Options", MDN + "X-Content-Type-Options")]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary, error = _primary_or_error(ctx)
        if error:
            return error
        value = (primary.headers.get("x-content-type-options") or "").strip()
        if value.lower() == "nosniff":
            return Outcome(CheckStatus.PASS, "X-Content-Type-Options is set to nosniff.")
        url = primary.final_url or ""
        f = self.finding(
            ctx,
            key="xcto",
            title="X-Content-Type-Options header is missing or incorrect",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            summary="Browsers are not told to trust the declared type of files from this site.",
            impact="Browsers may interpret uploaded or user-supplied files as scripts, which can "
            "help certain attacks succeed.",
            recommendation="Ask your web team to add `X-Content-Type-Options: nosniff`.",
            technical=f"X-Content-Type-Options: {value or 'not present'}",
            technical_remediation="Send `X-Content-Type-Options: nosniff` on all responses.",
            evidence=[("URL", url), ("X-Content-Type-Options", value or "not present")],
            affected_url=url,
        )
        return Outcome(CheckStatus.FINDING, "nosniff is not set.", [f])


class ReferrerPolicyCheck(Check):
    id = "referrer-policy"
    name = "Referrer-Policy"
    category = Category.BROWSER
    description = "Checks how much of the page address is shared with other websites."
    owasp = OWASP_MISCONFIG
    references = [("MDN: Referrer-Policy", MDN + "Referrer-Policy")]
    UNSAFE = {"unsafe-url", "no-referrer-when-downgrade"}

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary, error = _primary_or_error(ctx)
        if error:
            return error
        value = (primary.headers.get("referrer-policy") or "").strip()
        url = primary.final_url or ""
        policies = {p.strip().lower() for p in value.split(",") if p.strip()}
        if not value:
            f = self.finding(
                ctx,
                key="referrer-missing",
                title="Referrer-Policy header is not set",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="The website relies on the browser's default rules for sharing page "
                "addresses with other sites.",
                impact="Modern browsers apply a reasonable default, so the risk is limited. "
                "Setting it explicitly ensures consistent behaviour in all browsers.",
                recommendation="Optionally set `Referrer-Policy: strict-origin-when-cross-origin`.",
                technical="No Referrer-Policy header.",
                technical_remediation="Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
                evidence=[("URL", url), ("Referrer-Policy", "not present")],
                affected_url=url,
            )
            return Outcome(CheckStatus.FINDING, "Referrer-Policy not set (browser default applies).", [f])
        if policies & self.UNSAFE:
            f = self.finding(
                ctx,
                key="referrer-unsafe",
                title="Referrer-Policy shares full page addresses",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                summary="The website tells browsers to share full page addresses, which can "
                "include private details, with other websites.",
                impact="Addresses that contain identifiers or search terms may leak to third parties.",
                recommendation="Change the policy to `strict-origin-when-cross-origin`.",
                technical=f"Referrer-Policy: {value}",
                technical_remediation="Use `strict-origin-when-cross-origin`, `same-origin` or `no-referrer`.",
                evidence=[("Referrer-Policy", value)],
                affected_url=url,
            )
            return Outcome(CheckStatus.FINDING, "Referrer-Policy is permissive.", [f])
        return Outcome(CheckStatus.PASS, f"Referrer-Policy is {value}.")


class PermissionsPolicyCheck(Check):
    id = "permissions-policy"
    name = "Permissions-Policy"
    category = Category.BROWSER
    description = "Checks whether the site limits browser features such as camera and location."
    owasp = OWASP_MISCONFIG
    references = [("MDN: Permissions-Policy", MDN + "Permissions-Policy")]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary, error = _primary_or_error(ctx)
        if error:
            return error
        value = primary.headers.get("permissions-policy") or primary.headers.get("feature-policy")
        if value:
            return Outcome(CheckStatus.PASS, "A Permissions-Policy is set.")
        url = primary.final_url or ""
        f = self.finding(
            ctx,
            key="permissions-policy-missing",
            title="Permissions-Policy header is not set",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            summary="The website does not restrict which powerful browser features (camera, "
            "microphone, location) its pages and embedded content may request.",
            impact="This is a hardening measure. Without it, embedded third-party content could "
            "ask visitors for access to these features.",
            recommendation="Optionally add a Permissions-Policy that disables features you do not use.",
            technical="No Permissions-Policy header.",
            technical_remediation="For example: `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
            evidence=[("URL", url), ("Permissions-Policy", "not present")],
            affected_url=url,
        )
        return Outcome(CheckStatus.FINDING, "Permissions-Policy not set.", [f])


VERSION_RE = re.compile(r"\d+\.\d+")
DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-version",
]


class ServerDisclosureCheck(Check):
    id = "server-identification"
    name = "Server identification headers"
    category = Category.INFORMATION
    description = "Looks for headers that reveal server software and version numbers."
    owasp = OWASP_MISCONFIG

    def evaluate(self, ctx: ScanContext) -> Outcome:
        primary, error = _primary_or_error(ctx)
        if error:
            return error
        url = primary.final_url or ""
        disclosed = []
        for name in DISCLOSURE_HEADERS:
            value = primary.headers.get(name)
            if not value:
                continue
            if name == "server" and not VERSION_RE.search(value):
                continue  # product name only - common and low value
            disclosed.append((name, value))
        if not disclosed:
            return Outcome(CheckStatus.PASS, "No software version numbers disclosed in response headers.")
        f = self.finding(
            ctx,
            key="server-headers:" + ",".join(sorted(n for n, _ in disclosed)),
            title="Server software details are disclosed",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            summary="The website's responses reveal which software, and sometimes which version, "
            "runs the site.",
            impact="This helps attackers quickly look up known weaknesses for that exact software. "
            "On its own it is not a vulnerability, but it lowers the effort of an attack.",
            recommendation="Ask your web team to remove or generalise these headers and keep the "
            "software up to date.",
            technical="; ".join(f"{n}: {v}" for n, v in disclosed),
            technical_remediation="Disable version banners (e.g. `server_tokens off` in nginx, "
            "`ServerTokens Prod` in Apache, remove X-Powered-By in the application framework).",
            evidence=[(n, v) for n, v in disclosed],
            affected_url=url,
        )
        return Outcome(CheckStatus.FINDING, "Software identification headers found.", [f])

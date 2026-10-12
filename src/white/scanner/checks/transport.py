"""Connection protection checks: HTTPS, redirects, TLS certificate, HSTS."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from white.scanner.checks.base import Check, Outcome, ScanContext
from white.scanner.models import Category, CheckStatus, Confidence, Severity

OWASP_CRYPTO = "A04:2025 Cryptographic Failures"
OWASP_MISCONFIG = "A02:2025 Security Misconfiguration"


class HttpsAvailabilityCheck(Check):
    id = "https-availability"
    name = "HTTPS availability"
    category = Category.CONNECTION
    description = "Checks that the website answers over HTTPS with a certificate trusted by the client."
    owasp = OWASP_CRYPTO
    references = [
        (
            "MDN: Transport Layer Security",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        )
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        https = ctx.fetch_https()
        if https.ok:
            return Outcome(CheckStatus.PASS, f"HTTPS responded with HTTP status {https.status_code}.")
        if https.error_kind in {"blocked", "invalid"}:
            return Outcome(CheckStatus.ERROR, "HTTPS could not be tested safely.", errors=[https.error or ""])
        http = ctx.fetch_http()
        if https.error_kind == "tls":
            f = self.finding(
                ctx,
                key="untrusted-certificate",
                title="HTTPS certificate is not trusted",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="The website offers HTTPS, but its security certificate could not be verified.",
                impact="Visitors' browsers will show a security warning, which damages trust and "
                "can stop people using the site. An untrusted certificate also weakens protection "
                "against someone intercepting traffic.",
                recommendation="Ask your hosting provider or web team to install a valid certificate "
                "from a trusted authority (for example Let's Encrypt) and enable automatic renewal.",
                technical=f"TLS handshake or certificate verification failed: {https.error}",
                technical_remediation="Install a certificate chain issued by a publicly trusted CA "
                "that covers this hostname, include intermediate certificates, and ensure it has "
                "not expired.",
                evidence=[("HTTPS URL", ctx.https_url), ("Client error", https.error or "")],
                affected_url=ctx.https_url,
            )
            return Outcome(CheckStatus.FINDING, "The HTTPS certificate could not be verified.", [f])
        if http.ok:
            confidence = Confidence.MEDIUM if https.error_kind == "timeout" else Confidence.HIGH
            f = self.finding(
                ctx,
                key="https-unavailable",
                title="Website is not available over HTTPS",
                severity=Severity.HIGH,
                confidence=confidence,
                summary="The website answered over unencrypted HTTP but not over HTTPS.",
                impact="Information sent between visitors and the website, including anything typed "
                "into forms, can be read or changed by others on the same network. Browsers label "
                "such sites as 'Not secure'.",
                recommendation="Enable HTTPS for the website. Most hosting providers offer free "
                "certificates.",
                technical=f"HTTPS request failed ({https.error_kind}): {https.error}. "
                f"HTTP request succeeded with status {http.status_code}.",
                technical_remediation="Configure a TLS listener on port 443 with a valid "
                "certificate, then redirect all HTTP traffic to HTTPS.",
                evidence=[("HTTPS result", https.error or ""), ("HTTP status", str(http.status_code))],
                affected_url=ctx.http_url,
            )
            return Outcome(CheckStatus.FINDING, "HTTPS is not available.", [f])
        return Outcome(
            CheckStatus.ERROR,
            "Neither HTTPS nor HTTP responded, so availability could not be assessed.",
            errors=[f"HTTPS: {https.error}", f"HTTP: {http.error}"],
        )


class HttpRedirectCheck(Check):
    id = "http-to-https-redirect"
    name = "HTTP to HTTPS redirect"
    category = Category.CONNECTION
    description = "Checks that visitors who use http:// are sent to the secure https:// version."
    owasp = OWASP_CRYPTO

    def evaluate(self, ctx: ScanContext) -> Outcome:
        https = ctx.fetch_https()
        if not https.ok:
            return Outcome(
                CheckStatus.NOT_APPLICABLE,
                "HTTPS is not working, so a redirect to HTTPS cannot be expected (see HTTPS availability).",
            )
        http = ctx.fetch_http()
        if not http.ok:
            if http.error_kind in {"connect", "timeout"} and not http.hops:
                return Outcome(CheckStatus.PASS, "The website does not serve plain HTTP on port 80.")
            return Outcome(
                CheckStatus.INCONCLUSIVE,
                "The HTTP version could not be evaluated.",
                errors=[http.error or ""],
            )
        final = http.final_url or ""
        if final.startswith("https://"):
            first = http.hops[0]
            return Outcome(
                CheckStatus.PASS,
                f"http:// redirects to HTTPS (first response status {first.status_code}).",
            )
        f = self.finding(
            ctx,
            key="no-https-redirect",
            title="Visitors using http:// are not redirected to HTTPS",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            summary="The website still serves pages over unencrypted HTTP instead of sending "
            "visitors to the secure HTTPS version.",
            impact="People who type the address without https://, or follow old links, use an "
            "unencrypted connection where their activity can be observed or altered.",
            recommendation="Configure the website to permanently redirect all http:// requests to https://.",
            technical=f"GET {ctx.http_url} ended at {final} with status {http.status_code} "
            "without redirecting to an https:// URL.",
            technical_remediation="Return a 301 or 308 redirect from every HTTP URL to the "
            "equivalent HTTPS URL at the web server, load balancer or CDN.",
            evidence=[("Requested", ctx.http_url), ("Final URL", final), ("Status", str(http.status_code))],
            affected_url=ctx.http_url,
        )
        return Outcome(CheckStatus.FINDING, "HTTP is served without redirecting to HTTPS.", [f])


class TlsCertificateCheck(Check):
    id = "tls-certificate"
    name = "TLS certificate and protocol"
    category = Category.CONNECTION
    description = "Reports certificate expiry, issuer and the negotiated TLS version."
    owasp = OWASP_CRYPTO

    def evaluate(self, ctx: ScanContext) -> Outcome:
        https = ctx.fetch_https()
        if not https.ok:
            return Outcome(
                CheckStatus.NOT_TESTED,
                "HTTPS did not respond successfully, so the certificate details could not be read.",
            )
        tls = next((h.tls for h in https.hops if h.tls is not None), None)
        if tls is None or tls.not_after is None:
            return Outcome(
                CheckStatus.INCONCLUSIVE, "Certificate details were not available from the connection."
            )
        days_left = (tls.not_after - datetime.now(UTC)).days
        details = (
            f"Issuer: {tls.issuer or 'unknown'}; expires {tls.not_after:%Y-%m-%d} "
            f"({days_left} days); protocol {tls.version or 'unknown'}"
        )
        evidence = [
            ("Issuer", tls.issuer or "unknown"),
            ("Subject", tls.subject or "unknown"),
            ("Valid until", f"{tls.not_after:%Y-%m-%d %H:%M} UTC"),
            ("Days remaining", str(days_left)),
            ("Protocol", tls.version or "unknown"),
            ("Cipher", tls.cipher or "unknown"),
        ]
        findings = []
        if days_left < 30:
            severity = Severity.MEDIUM if days_left < 14 else Severity.LOW
            findings.append(
                self.finding(
                    ctx,
                    key="certificate-expiring",
                    title="HTTPS certificate expires soon",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    summary=f"The website's security certificate expires in {days_left} days.",
                    impact="If the certificate is not renewed in time, browsers will block visitors "
                    "with a full-page security warning.",
                    recommendation="Renew the certificate now and set up automatic renewal.",
                    technical=details,
                    technical_remediation="Renew the certificate and automate renewal (for example "
                    "with an ACME client such as certbot), then monitor expiry.",
                    evidence=evidence,
                    affected_url=ctx.https_url,
                )
            )
        if tls.version in {"TLSv1", "TLSv1.1", "SSLv3"}:
            findings.append(
                self.finding(
                    ctx,
                    key="legacy-tls",
                    title="Outdated TLS protocol negotiated",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary="The connection used an outdated encryption protocol.",
                    impact="Old protocols have known weaknesses and are rejected by modern browsers.",
                    recommendation="Ask your hosting provider to allow only TLS 1.2 and TLS 1.3.",
                    technical=details,
                    technical_remediation="Disable SSLv3, TLS 1.0 and TLS 1.1 in the server configuration.",
                    evidence=evidence,
                    affected_url=ctx.https_url,
                )
            )
        if findings:
            return Outcome(CheckStatus.FINDING, details, findings)
        return Outcome(CheckStatus.PASS, details)


class HstsCheck(Check):
    id = "hsts"
    name = "HTTP Strict Transport Security (HSTS)"
    category = Category.CONNECTION
    description = "Checks that browsers are told to always use HTTPS for this site."
    owasp = OWASP_CRYPTO
    references = [
        (
            "MDN: Strict-Transport-Security",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        )
    ]
    MIN_AGE = 15_552_000  # 180 days

    def evaluate(self, ctx: ScanContext) -> Outcome:
        https = ctx.fetch_https()
        if not https.ok or not (https.final_url or "").startswith("https://"):
            return Outcome(CheckStatus.NOT_APPLICABLE, "HSTS only applies to sites served over HTTPS.")
        value = https.headers.get("strict-transport-security")
        if not value:
            f = self.finding(
                ctx,
                key="hsts-missing",
                title="HSTS header is missing",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                summary="The website does not tell browsers to always use the secure HTTPS connection.",
                impact="A visitor's first request, or a link using http://, could be intercepted and "
                "downgraded to an unencrypted connection on untrusted networks such as public Wi-Fi.",
                recommendation="Ask your web team to add the Strict-Transport-Security header.",
                technical="No Strict-Transport-Security header on the final HTTPS response.",
                technical_remediation="Send `Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains` on HTTPS responses once all subdomains support HTTPS.",
                evidence=[("URL", https.final_url or ""), ("Header", "not present")],
                affected_url=https.final_url,
            )
            return Outcome(CheckStatus.FINDING, "Strict-Transport-Security header not present.", [f])
        max_age = None
        for part in value.split(";"):
            name, _, raw = part.strip().partition("=")
            if name.strip().lower() == "max-age":
                try:
                    max_age = int(raw.strip().strip('"'))
                except ValueError:
                    max_age = None
        if max_age is None or max_age < self.MIN_AGE:
            f = self.finding(
                ctx,
                key="hsts-weak",
                title="HSTS protection period is too short or invalid",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                summary="The HSTS header is present but its duration is missing, invalid or shorter "
                "than the recommended 180 days.",
                impact="Browsers forget the HTTPS-only rule quickly, reducing the protection.",
                recommendation="Increase the HSTS max-age to at least one year.",
                technical=f"Strict-Transport-Security: {value}",
                technical_remediation="Use max-age=31536000 (one year) or more.",
                evidence=[("Header", value)],
                affected_url=https.final_url,
            )
            return Outcome(CheckStatus.FINDING, "HSTS max-age is weak.", [f])
        return Outcome(CheckStatus.PASS, f"HSTS is enabled (max-age={max_age}).")


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _same_site(a: str, b: str) -> bool:
    a, b = a.removeprefix("www."), b.removeprefix("www.")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


class RedirectSafetyCheck(Check):
    id = "redirect-behaviour"
    name = "Redirect behaviour"
    category = Category.CONFIGURATION
    description = "Looks for redirects that downgrade to HTTP or send visitors to another domain."
    owasp = OWASP_MISCONFIG

    def evaluate(self, ctx: ScanContext) -> Outcome:
        chains = [r for r in (ctx.fetch_https(), ctx.fetch_http()) if r.hops]
        if not chains:
            primary = ctx.primary()
            return Outcome(CheckStatus.ERROR, "No responses were received.", errors=[primary.error or ""])
        findings = []
        errors = [r.error for r in chains if r.error_kind in {"redirect", "blocked"} and r.error]
        for chain in chains:
            for previous, current in zip(chain.hops, chain.hops[1:], strict=False):
                if previous.url.startswith("https://") and current.url.startswith("http://"):
                    findings.append(
                        self.finding(
                            ctx,
                            key=f"downgrade:{_host(current.url)}",
                            title="Redirect downgrades from HTTPS to HTTP",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            summary="A secure page redirects visitors to an unencrypted address.",
                            impact="Visitors lose the protection of encryption during navigation, "
                            "allowing traffic to be read or modified.",
                            recommendation="Update the redirect so it always points to an https:// address.",
                            technical=f"{previous.url} responded {previous.status_code} with "
                            f"Location: {previous.location}",
                            technical_remediation="Change redirect targets to HTTPS URLs.",
                            evidence=[
                                ("From", previous.url),
                                ("To", current.url),
                                ("Status", str(previous.status_code)),
                            ],
                            affected_url=previous.url,
                        )
                    )
                    break
        primary = ctx.primary()
        if primary.ok and primary.final_url:
            final_host = _host(primary.final_url)
            if final_host and not _same_site(final_host, ctx.target.host):
                findings.append(
                    self.finding(
                        ctx,
                        key=f"offsite:{final_host}",
                        title="Website redirects to a different domain",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        summary=f"Visitors to {ctx.target.host} are sent to {final_host}.",
                        impact="This is often intentional, but an unexpected redirect can indicate a "
                        "misconfiguration or a compromised site. Confirm it is expected.",
                        recommendation="Confirm that this redirect is intentional.",
                        technical=" -> ".join(h.url for h in primary.hops),
                        technical_remediation="If unexpected, review web server, CDN and DNS settings.",
                        evidence=[("Redirect chain", " -> ".join(h.url for h in primary.hops))],
                        affected_url=ctx.target.url,
                    )
                )
                findings[-1].status = CheckStatus.POTENTIAL
        if findings:
            status = (
                CheckStatus.FINDING
                if any(f.status == CheckStatus.FINDING for f in findings)
                else CheckStatus.POTENTIAL
            )
            return Outcome(status, "Redirect behaviour needs attention.", findings, errors)
        if errors:
            return Outcome(CheckStatus.INCONCLUSIVE, "Some redirects could not be followed.", errors=errors)
        return Outcome(CheckStatus.PASS, "No HTTPS downgrades or unexpected cross-domain redirects observed.")

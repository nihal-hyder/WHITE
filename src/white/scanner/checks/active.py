"""Opt-in, conservative input-handling indicators (reflected XSS, SQL error disclosure).

These checks send a small number of harmless GET requests with a unique marker. They never
submit forms, never use POST, never attempt exploitation and never alter data. Results are
indicators (POTENTIAL) that need manual confirmation. They only run when active checks are
explicitly enabled for an authorized target; otherwise they report NOT_TESTED.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from white.scanner.checks.base import Check, Outcome, ScanContext, unreachable
from white.scanner.models import Category, CheckStatus, Confidence, Severity

MAX_PARAMS = 3
DISABLED = (
    "Active input checks are disabled. Enable them only for sites you are authorized to "
    "test (CLI: --active-checks, GUI: 'Include active input checks')."
)


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    new = []
    for key, current in params:
        if key == name and not replaced:
            new.append((key, value))
            replaced = True
        else:
            new.append((key, current))
    if not replaced:
        new.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new), ""))


def _param_names(url: str) -> list[str]:
    names = []
    for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key not in names:
            names.append(key)
    return names[:MAX_PARAMS]


class ReflectedXssIndicatorCheck(Check):
    id = "reflected-xss-indicator"
    name = "Reflected input indicator (XSS)"
    category = Category.INPUT
    description = (
        "Opt-in. Sends a harmless unique marker containing HTML characters in up to three "
        "URL parameters and checks whether it is reflected without encoding."
    )
    owasp = "A05:2025 Injection"
    active = True
    references = [
        (
            "OWASP XSS Prevention Cheat Sheet",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        )
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        if not ctx.config.active_checks:
            return Outcome(CheckStatus.NOT_TESTED, DISABLED)
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        base = primary.final_url or ctx.target.url
        names = _param_names(base) or ["white_probe"]
        findings, tested = [], 0
        for name in names:
            token = secrets.token_hex(4)
            marker = f"<wht{token}>"
            probe = f"wht{token}\"'{marker}"
            url = _with_param(base, name, probe)
            response = ctx.client.fetch(url, follow_redirects=False, use_cache=False)
            if not response.ok:
                continue
            tested += 1
            if response.is_html and marker in response.text:
                findings.append(
                    self.finding(
                        ctx,
                        key=f"xss:{name}",
                        title=f"Input in parameter '{name}' is reflected without encoding",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        status=CheckStatus.POTENTIAL,
                        summary="Text placed in the page address appears in the page exactly as sent, "
                        "including HTML characters.",
                        impact="This pattern is a common precondition for cross-site scripting, where an "
                        "attacker's link runs code in a visitor's browser. It needs manual confirmation; "
                        "WHITE did not attempt to run any script.",
                        recommendation="Ask a developer or security tester to review how this page "
                        "displays the parameter and to apply output encoding.",
                        technical=f"Marker {marker!r} sent in parameter '{name}' was reflected unencoded "
                        "in an HTML response.",
                        technical_remediation="Context-aware output encoding for all reflected input, plus "
                        "a strict Content-Security-Policy.",
                        evidence=[
                            ("Parameter", name),
                            ("Marker", marker),
                            ("Response status", str(response.status_code)),
                        ],
                        affected_url=url,
                    )
                )
        if tested == 0:
            return Outcome(CheckStatus.INCONCLUSIVE, "No probe request completed successfully.")
        if findings:
            return Outcome(CheckStatus.POTENTIAL, "Unencoded reflection observed.", findings)
        return Outcome(CheckStatus.PASS, f"Marker was not reflected unencoded in {tested} parameter(s).")


SQL_ERRORS = re.compile(
    r"(You have an error in your SQL syntax|Warning: mysqli?_|Unclosed quotation mark after the "
    r"character string|quoted string not properly terminated|PG::SyntaxError|pg_query\(\)|"
    r"SQLSTATE\[|ORA-0\d{4}|SQLite3?::|sqlite3\.OperationalError|Microsoft OLE DB Provider for SQL Server|"
    r"syntax error at or near)",
    re.I,
)


class SqlErrorIndicatorCheck(Check):
    id = "sql-error-indicator"
    name = "Database error indicator (SQL injection)"
    category = Category.INPUT
    description = (
        "Opt-in. Adds a single quote to up to three existing URL parameters and checks "
        "for new database error messages. Read-only GET requests only."
    )
    owasp = "A05:2025 Injection"
    active = True
    references = [
        (
            "OWASP SQL Injection Prevention Cheat Sheet",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        )
    ]

    def evaluate(self, ctx: ScanContext) -> Outcome:
        if not ctx.config.active_checks:
            return Outcome(CheckStatus.NOT_TESTED, DISABLED)
        primary = ctx.primary()
        if not primary.ok:
            return unreachable(primary)
        base = primary.final_url or ctx.target.url
        names = _param_names(base)
        if not names:
            return Outcome(
                CheckStatus.NOT_APPLICABLE,
                "The scanned URL has no query parameters to test. "
                "Scan a URL that includes parameters (e.g. ?id=1) to use this check.",
            )
        baseline_has_error = bool(SQL_ERRORS.search(primary.text))
        findings, tested = [], 0
        params = dict(parse_qsl(urlsplit(base).query, keep_blank_values=True))
        for name in names:
            url = _with_param(base, name, params.get(name, "") + "'")
            response = ctx.client.fetch(url, follow_redirects=False, use_cache=False)
            if not response.ok:
                continue
            tested += 1
            match = SQL_ERRORS.search(response.text)
            if match and not baseline_has_error:
                findings.append(
                    self.finding(
                        ctx,
                        key=f"sqli:{name}",
                        title=f"Database error triggered by parameter '{name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        status=CheckStatus.POTENTIAL,
                        summary="Adding a single quote character to the page address caused a database "
                        "error message to appear.",
                        impact="This suggests input may be passed to the database without proper "
                        "handling (SQL injection), which could allow data theft. It needs manual "
                        "confirmation; WHITE did not attempt to extract any data.",
                        recommendation="Ask a developer or security tester to review this parameter "
                        "urgently and use parameterised database queries.",
                        technical=f"Appending ' to '{name}' produced a response matching a database "
                        f"error signature: {match.group(0)!r}. The baseline page did not.",
                        technical_remediation="Use parameterised queries/prepared statements and "
                        "generic error pages.",
                        evidence=[
                            ("Parameter", name),
                            ("Error signature", match.group(0)),
                            ("Response status", str(response.status_code)),
                        ],
                        affected_url=url,
                    )
                )
        if tested == 0:
            return Outcome(CheckStatus.INCONCLUSIVE, "No probe request completed successfully.")
        if baseline_has_error and not findings:
            return Outcome(
                CheckStatus.INCONCLUSIVE,
                "The page already shows database errors without "
                "modified input, so this indicator cannot be evaluated.",
            )
        if findings:
            return Outcome(CheckStatus.POTENTIAL, "Database error indicator observed.", findings)
        return Outcome(CheckStatus.PASS, f"No database errors triggered in {tested} parameter(s).")

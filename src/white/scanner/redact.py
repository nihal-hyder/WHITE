"""Redaction helpers so evidence never carries secrets or excessive response content."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_PARAM = re.compile(
    r"(pass|pwd|secret|token|key|auth|session|sid|code|signature|sig|jwt|bearer|cred)", re.I
)
_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{8,}"), "[REDACTED-API-KEY]"),
    (re.compile(r"\bsb_secret_[A-Za-z0-9_-]{8,}"), "[REDACTED-API-KEY]"),
    (
        re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['\"]?[^\s'\"&<]{3,}"),
        r"\1=[REDACTED]",
    ),
]
MAX_EVIDENCE_CHARS = 300


def redact_text(value: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = value
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def redact_url(url: str | None) -> str | None:
    """Remove credentials and sensitive query values from a URL."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[unparseable URL]"
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    query = urlencode(
        [
            (k, "[REDACTED]" if SENSITIVE_PARAM.search(k) else v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def redact_cookie(set_cookie: str) -> str:
    """Show a cookie's name and attributes but never its value."""
    head, _, attributes = set_cookie.partition(";")
    name = head.split("=", 1)[0].strip()
    attrs = "; ".join(a.strip() for a in attributes.split(";") if a.strip())
    return f"{name}=[value hidden]" + (f"; {attrs}" if attrs else "")

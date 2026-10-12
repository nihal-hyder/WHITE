"""Bounded, SSRF-safe HTTP client used by all checks."""

from __future__ import annotations

import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

import httpx

from white.scanner.models import ScanConfig
from white.scanner.netsafety import (
    BlockedDestinationError,
    SafeTransport,
    TargetValidationError,
    validate_target_url,
)

REDIRECT_CODES = {301, 302, 303, 307, 308}


class ScanCancelled(Exception):
    """Raised when the user cancels a scan."""


class ScanBudgetExceeded(Exception):
    """Raised when the per-scan request or time budget is exhausted."""


@dataclass
class TLSInfo:
    version: str | None = None
    cipher: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    subject: str | None = None
    issuer: str | None = None
    san: list[str] = field(default_factory=list)


@dataclass
class Hop:
    url: str
    status_code: int
    headers: httpx.Headers
    location: str | None = None
    tls: TLSInfo | None = None


@dataclass
class FetchResult:
    requested_url: str
    hops: list[Hop] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    error_kind: str | None = None  # blocked | timeout | tls | connect | redirect | invalid | http
    error: str | None = None
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.error_kind is None and bool(self.hops)

    @property
    def final(self) -> Hop | None:
        return self.hops[-1] if self.hops else None

    @property
    def final_url(self) -> str | None:
        return self.final.url if self.final else None

    @property
    def status_code(self) -> int | None:
        return self.final.status_code if self.final else None

    @property
    def headers(self) -> httpx.Headers:
        return self.final.headers if self.final else httpx.Headers()

    @property
    def text(self) -> str:
        charset = "utf-8"
        content_type = self.headers.get("content-type", "")
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_html(self) -> bool:
        return "html" in self.headers.get("content-type", "").lower()


def _name_to_str(name: Any) -> str:
    try:
        return ", ".join(f"{k}={v}" for rdn in name for (k, v) in rdn)
    except (TypeError, ValueError):
        return str(name)


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)
    except (ValueError, OverflowError):
        return None


def _extract_tls(response: httpx.Response) -> TLSInfo | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    ssl_object = stream.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    info = TLSInfo(version=ssl_object.version())
    cipher = ssl_object.cipher()
    if cipher:
        info.cipher = cipher[0]
    cert = ssl_object.getpeercert() or {}
    info.not_before = _parse_cert_time(cert.get("notBefore"))
    info.not_after = _parse_cert_time(cert.get("notAfter"))
    info.subject = _name_to_str(cert.get("subject", ()))
    info.issuer = _name_to_str(cert.get("issuer", ()))
    info.san = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"][:20]
    return info


def classify_error(exc: Exception) -> tuple[str, str]:
    """Map an exception to (kind, safe message)."""
    if isinstance(exc, BlockedDestinationError):
        return "blocked", f"Destination blocked by safety policy: {exc}"
    if isinstance(exc, TargetValidationError):
        return "invalid", str(exc)
    if isinstance(exc, httpx.TimeoutException):
        return "timeout", "The website did not respond before the time limit."
    message = str(exc)
    if isinstance(exc, httpx.ConnectError | httpx.ReadError | httpx.RemoteProtocolError):
        lowered = message.lower()
        if "certificate" in lowered or "ssl" in lowered or "tls" in lowered:
            return "tls", f"TLS/certificate error: {message[:300]}"
        if "dns resolution failed" in lowered or "getaddrinfo" in lowered:
            return "connect", "The hostname could not be resolved (DNS lookup failed)."
        return "connect", f"Connection failed: {message[:300] or exc.__class__.__name__}"
    if isinstance(exc, httpx.HTTPError):
        return "http", f"HTTP error: {message[:300] or exc.__class__.__name__}"
    return "error", f"Unexpected error: {exc.__class__.__name__}"


class SafeHttpClient:
    """HTTP client with redirect revalidation, size/time/request budgets and caching.

    ``transport`` can be injected for tests (e.g. ``httpx.MockTransport``). In that case the
    connection-level IP checks of :class:`SafeTransport` are not exercised, but URL validation
    of the target and of every redirect still is.
    """

    def __init__(
        self,
        config: ScanConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        cancel_event: threading.Event | None = None,
        deadline: float | None = None,
    ) -> None:
        self.config = config
        self.cancel_event = cancel_event or threading.Event()
        self.deadline = deadline or (time.monotonic() + config.max_scan_seconds)
        self.requests_made = 0
        self._last_request = 0.0
        self._cache: dict[tuple[str, str], FetchResult] = {}
        self._lock = threading.Lock()
        self._client = httpx.Client(
            transport=transport or SafeTransport(config),
            follow_redirects=False,
            trust_env=False,  # never route through environment proxies
            timeout=httpx.Timeout(config.request_timeout),
            headers={"User-Agent": config.user_agent, "Accept": "*/*"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeHttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def check_budget(self) -> None:
        if self.cancel_event.is_set():
            raise ScanCancelled()
        if time.monotonic() > self.deadline:
            raise ScanBudgetExceeded("The scan time limit was reached.")
        if self.requests_made >= self.config.max_requests:
            raise ScanBudgetExceeded("The scan request limit was reached.")

    def _throttle(self) -> None:
        wait = self.config.min_request_interval - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        read_body: bool = True,
        use_cache: bool = True,
    ) -> FetchResult:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError("WHITE only issues GET and HEAD requests")
        key = (f"{method}:{follow_redirects}:{read_body}", url)
        if use_cache and key in self._cache:
            return self._cache[key]
        result = FetchResult(requested_url=url)
        started = time.monotonic()
        current = url
        try:
            for _ in range(self.config.max_redirects + 1):
                validate_target_url(current, self.config)
                with self._lock:
                    self.check_budget()
                    self._throttle()
                    self.requests_made += 1
                with self._client.stream(method, current) as response:
                    hop = Hop(
                        url=current,
                        status_code=response.status_code,
                        headers=response.headers,
                        tls=_extract_tls(response) if current.startswith("https://") else None,
                    )
                    location = response.headers.get("location")
                    is_redirect = response.status_code in REDIRECT_CODES and location
                    if is_redirect:
                        hop.location = urljoin(current, location.strip())
                    result.hops.append(hop)
                    if is_redirect and follow_redirects:
                        current = hop.location  # type: ignore[assignment]
                        continue
                    if read_body and method == "GET":
                        result.body, result.truncated = self._read_limited(response)
                    break
            else:
                result.error_kind = "redirect"
                result.error = f"More than {self.config.max_redirects} redirects."
        except (ScanCancelled, ScanBudgetExceeded):
            raise
        except TargetValidationError as exc:
            result.error_kind = "blocked" if result.hops else "invalid"
            prefix = "Redirect destination rejected: " if result.hops else ""
            result.error = f"{prefix}{exc}"
        except Exception as exc:  # noqa: BLE001 - classified and reported, never swallowed silently
            result.error_kind, result.error = classify_error(exc)
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        if use_cache:
            self._cache[key] = result
        return result

    def _read_limited(self, response: httpx.Response) -> tuple[bytes, bool]:
        limit = self.config.max_response_bytes
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= limit:
                return b"".join(chunks)[:limit], True
        return b"".join(chunks), False

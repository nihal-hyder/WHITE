"""SafeHttpClient: timeouts, connection errors, size and request budgets, cancellation."""

from __future__ import annotations

import threading

import httpx
import pytest

from white.scanner.http import SafeHttpClient, ScanBudgetExceeded, ScanCancelled
from white.scanner.models import ScanConfig


def client_for(handler, **cfg) -> SafeHttpClient:
    return SafeHttpClient(ScanConfig(min_request_interval=0, **cfg), transport=httpx.MockTransport(handler))


def test_timeout_is_classified():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    result = client_for(handler).fetch("https://shop.example.com/")
    assert result.error_kind == "timeout" and not result.ok


def test_connection_error_is_classified():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    assert client_for(handler).fetch("https://shop.example.com/").error_kind == "connect"


def test_tls_error_is_classified():
    def handler(request):
        raise httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=request
        )

    assert client_for(handler).fetch("https://shop.example.com/").error_kind == "tls"


def test_response_size_limit_truncates():
    def handler(request):
        return httpx.Response(200, content=b"x" * 50_000)

    result = client_for(handler, max_response_bytes=10_000).fetch("https://shop.example.com/")
    assert result.truncated and len(result.body) == 10_000


def test_redirect_limit():
    def handler(request):
        n = int(request.url.params.get("n", "0"))
        return httpx.Response(302, headers={"location": f"/?n={n + 1}"})

    result = client_for(handler, max_redirects=3).fetch("https://shop.example.com/")
    assert result.error_kind == "redirect" and len(result.hops) == 4


def test_request_budget_enforced():
    client = client_for(lambda r: httpx.Response(200), max_requests=2)
    client.fetch("https://shop.example.com/a")
    client.fetch("https://shop.example.com/b")
    with pytest.raises(ScanBudgetExceeded):
        client.fetch("https://shop.example.com/c")


def test_cancellation():
    event = threading.Event()
    event.set()
    client = SafeHttpClient(
        ScanConfig(), transport=httpx.MockTransport(lambda r: httpx.Response(200)), cancel_event=event
    )
    with pytest.raises(ScanCancelled):
        client.fetch("https://shop.example.com/")


def test_only_get_and_head_allowed():
    client = client_for(lambda r: httpx.Response(200))
    with pytest.raises(ValueError):
        client.fetch("https://shop.example.com/", method="POST")


def test_results_are_cached():
    calls = []
    client = client_for(lambda r: calls.append(1) or httpx.Response(200))
    client.fetch("https://shop.example.com/")
    client.fetch("https://shop.example.com/")
    assert len(calls) == 1

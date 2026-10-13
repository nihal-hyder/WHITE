"""URL validation, private-address blocking, DNS validation and connection-level enforcement."""

from __future__ import annotations

import ipaddress
import socket

import httpcore
import httpx
import pytest

from white.scanner.http import SafeHttpClient
from white.scanner.models import ScanConfig
from white.scanner.netsafety import (
    BlockedDestinationError,
    SafeNetworkBackend,
    TargetValidationError,
    ip_block_reason,
    normalize_user_url,
    resolve_and_validate,
    validate_target_url,
)

CFG = ScanConfig()


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com",
        "data:text/html,hi",
        "ws://example.com",
        "//example.com",
    ],
)
def test_unsupported_schemes_rejected(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, CFG)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.com/",
        "https://user@example.com/",
        "https://example.com@evil.com/",
    ],
)
def test_embedded_credentials_rejected(url):
    with pytest.raises(TargetValidationError, match="usernames or passwords"):
        validate_target_url(url, CFG)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://foo.localhost/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://0.0.0.0/",
        "http://[::ffff:127.0.0.1]/",
        "http://100.64.0.1/",
        "http://224.0.0.1/",
        "http://metadata.google.internal/",
        "http://printer.local/",
        "http://intranet/",
    ],
)
def test_private_and_special_destinations_rejected(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, CFG)


def test_ports_restricted():
    with pytest.raises(TargetValidationError, match="Port 22"):
        validate_target_url("https://example.com:22/", CFG)
    assert validate_target_url("https://example.com:8443/", CFG).port == 8443


def test_port_allowlist_relaxed_for_local_scanning():
    # Opting into private/local scanning permits any web port (e.g. a second dev server on 8444)
    # but never relaxes the address rules: cloud metadata and the like stay blocked.
    dev = ScanConfig(allow_private_targets=True)
    assert validate_target_url("http://127.0.0.1:8444/", dev).port == 8444
    assert resolve_and_validate("127.0.0.1", 8444, dev) == ["127.0.0.1"]
    with pytest.raises(TargetValidationError):
        validate_target_url("http://169.254.169.254:8444/", dev)


def test_valid_url_normalized():
    target = validate_target_url("HTTPS://Example.COM", CFG)
    assert target.url == "https://example.com/"
    assert target.host == "example.com" and target.port == 443
    assert validate_target_url("https://example.com/a?b=1#frag", CFG).url == "https://example.com/a?b=1"


def test_idn_hostname_is_punycoded():
    assert validate_target_url("https://bücher.example/", CFG).host == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "https://exa mple.com", "https://example.com\\@evil.com", "https://" + "a" * 3000 + ".com"],
)
def test_malformed_rejected(raw):
    with pytest.raises(TargetValidationError):
        validate_target_url(raw, CFG)


def test_normalize_adds_https():
    assert normalize_user_url(" example.com ") == "https://example.com"
    assert normalize_user_url("http://x.com") == "http://x.com"


def test_allow_private_permits_loopback_but_never_metadata():
    cfg = ScanConfig(allow_private_targets=True)
    assert validate_target_url("http://127.0.0.1:8080/", cfg).host == "127.0.0.1"
    with pytest.raises(TargetValidationError):
        validate_target_url("http://169.254.169.254/", cfg)
    assert ip_block_reason(ipaddress.ip_address("fd00:ec2::254"), allow_private=True)


def test_ip_classification():
    assert ip_block_reason(ipaddress.ip_address("93.184.216.34")) is None
    assert ip_block_reason(ipaddress.ip_address("2606:4700::1111")) is None
    assert ip_block_reason(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert ip_block_reason(ipaddress.ip_address("2002:7f00:0001::1"))  # 6to4 wrapping 127.0.0.1


def _fake_getaddrinfo(addresses):
    def fake(host, port, *args, **kwargs):
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
            for a in addresses
        ]

    return fake


def test_dns_resolving_to_private_address_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(["10.1.2.3"]))
    with pytest.raises(BlockedDestinationError):
        resolve_and_validate("evil.example.com", 443, CFG)


def test_mixed_public_and_private_resolution_fails_closed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34", "127.0.0.1"]))
    with pytest.raises(BlockedDestinationError):
        resolve_and_validate("rebind.example.com", 443, CFG)


def test_ipv6_private_resolution_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(["fc00::1"]))
    with pytest.raises(BlockedDestinationError):
        resolve_and_validate("v6.example.com", 443, CFG)


def test_dns_failure_is_connect_error(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(httpcore.ConnectError):
        resolve_and_validate("missing.example.com", 443, CFG)


def test_backend_connects_only_to_the_validated_address(monkeypatch):
    """DNS rebinding defence: the connection uses the exact address that was validated."""
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])  # a second lookup would rebind
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _fake_getaddrinfo(next(answers))(*a, **k))
    connected = []
    monkeypatch.setattr(
        httpcore.SyncBackend, "connect_tcp", lambda self, host, port, **kw: connected.append(host) or "stream"
    )
    backend = SafeNetworkBackend(CFG)
    assert backend.connect_tcp("rebind.example.com", 443) == "stream"
    assert connected == ["93.184.216.34"]


def test_backend_refuses_loopback_at_connection_time():
    with pytest.raises(BlockedDestinationError):
        SafeNetworkBackend(CFG).connect_tcp("127.0.0.1", 80)


def test_backend_refuses_disallowed_port():
    with pytest.raises(BlockedDestinationError):
        SafeNetworkBackend(CFG).connect_tcp("93.184.216.34", 6379)


def test_real_client_blocks_loopback_without_mock():
    """End-to-end through the real SafeTransport: the request never reaches a socket."""
    with SafeHttpClient(ScanConfig(min_request_interval=0)) as client:
        result = client.fetch("http://127.0.0.1/")
    assert result.error_kind == "invalid"
    # With private targets allowed for URL syntax, the connection layer still refuses metadata IPs.
    with SafeHttpClient(ScanConfig(min_request_interval=0, allow_private_targets=True)) as client:
        result = client.fetch("http://[fd00:ec2::254]/")
    assert result.error_kind in {"invalid", "blocked"}


def test_redirect_to_private_address_rejected():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    with SafeHttpClient(ScanConfig(min_request_interval=0), transport=httpx.MockTransport(handler)) as c:
        result = c.fetch("https://shop.example.com/")
    assert result.error_kind == "blocked"
    assert "Redirect destination rejected" in (result.error or "")
    assert len(result.hops) == 1


@pytest.mark.parametrize(
    "location", ["file:///etc/passwd", "https://user:pw@example.org/", "https://example.org:6379/"]
)
def test_redirect_to_unsafe_url_rejected(location):
    def handler(request):
        return httpx.Response(301, headers={"location": location})

    with SafeHttpClient(ScanConfig(min_request_interval=0), transport=httpx.MockTransport(handler)) as c:
        result = c.fetch("https://shop.example.com/")
    assert result.error_kind == "blocked"


def test_proxy_environment_is_ignored(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    client = SafeHttpClient(ScanConfig())
    assert client._client._mounts == {}  # noqa: SLF001 - no proxy transports mounted
    client.close()

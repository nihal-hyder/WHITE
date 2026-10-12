"""Network-boundary protections (SSRF defence) for every request the scanner makes.

Design:
* ``validate_target_url`` performs strict syntactic validation (scheme, credentials, port, host).
* ``SafeNetworkBackend`` is an httpcore network backend. Every TCP connection - including the
  ones made for redirects - resolves the hostname once, validates *every* resolved address and
  then connects to one of those validated addresses. Because the address that was checked is the
  address that is connected to, DNS rebinding / time-of-check-time-of-use tricks cannot swap in
  an internal address between validation and connection. TLS SNI and certificate verification
  still use the original hostname.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpcore
import httpx

from white.scanner.models import ScanConfig

# Addresses that are never allowed, even when private targets are explicitly permitted.
ALWAYS_BLOCKED = {
    ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure/OpenStack metadata
    ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata
    ipaddress.ip_address("168.63.129.16"),  # Azure wire server
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 metadata
}

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".lan")
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata", "metadata.google.internal"}
MAX_URL_LENGTH = 2048


class TargetValidationError(ValueError):
    """The URL is malformed or not permitted. The message is safe to show to users."""


class BlockedDestinationError(Exception):
    """A connection was refused because the destination address is not permitted."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self._host_for_url}{port}"

    @property
    def _host_for_url(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host


def normalize_user_url(raw: str) -> str:
    """Add https:// when the user typed only a hostname."""
    value = (raw or "").strip()
    if value and "://" not in value:
        value = "https://" + value
    return value


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]").split("%")[0])
    except ValueError:
        return None


def ip_block_reason(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool = False
) -> str | None:
    """Return why ``ip`` may not be contacted, or ``None`` when it is allowed."""
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return ip_block_reason(mapped, allow_private=allow_private)
        if ip.teredo is not None:
            return "Teredo tunnelled addresses are not permitted"
    if ip in ALWAYS_BLOCKED:
        return "cloud metadata addresses are never permitted"
    if ip.is_unspecified:
        return "unspecified addresses are not permitted"
    if ip.is_multicast:
        return "multicast addresses are not permitted"
    if ip.is_link_local:
        return "link-local addresses are not permitted"
    if allow_private and (ip.is_loopback or ip.is_private):
        return None
    if ip.is_loopback:
        return "loopback addresses are not permitted"
    if ip.is_private:
        return "private network addresses are not permitted"
    if ip.is_reserved:
        return "reserved addresses are not permitted"
    if not ip.is_global:
        return "non-public addresses are not permitted"
    return None


def validate_target_url(raw_url: str, config: ScanConfig | None = None) -> ValidatedTarget:
    """Strictly validate a URL before any network activity."""
    config = config or ScanConfig()
    if not raw_url or not raw_url.strip():
        raise TargetValidationError("Enter a website address, for example https://example.com.")
    url = raw_url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise TargetValidationError("The URL is too long.")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in url):
        raise TargetValidationError("The URL contains spaces or control characters.")
    if "\\" in url:
        raise TargetValidationError("The URL contains a backslash, which is not permitted.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError("The URL could not be parsed.") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("Only http:// and https:// addresses can be scanned.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetValidationError("URLs containing usernames or passwords are not permitted.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise TargetValidationError("The URL does not contain a hostname.")
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in config.allowed_ports:
        allowed = ", ".join(str(p) for p in config.allowed_ports)
        raise TargetValidationError(f"Port {port} is not permitted. Allowed ports: {allowed}.")

    ip = _parse_ip(host)
    if ip is not None:
        reason = ip_block_reason(ip, allow_private=config.allow_private_targets)
        if reason:
            raise TargetValidationError(f"This address cannot be scanned: {reason}.")
        host = str(ip)
    else:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetValidationError("The hostname is not valid.") from exc
        labels = ascii_host.split(".")
        if any(not label or len(label) > 63 for label in labels) or len(ascii_host) > 253:
            raise TargetValidationError("The hostname is not valid.")
        if not all(ch.isalnum() or ch in "-." for ch in ascii_host):
            raise TargetValidationError("The hostname contains characters that are not permitted.")
        if not config.allow_private_targets and (
            ascii_host in BLOCKED_HOSTNAMES or ascii_host.endswith(BLOCKED_HOST_SUFFIXES)
        ):
            raise TargetValidationError("Local and internal hostnames cannot be scanned.")
        if "." not in ascii_host and not config.allow_private_targets:
            raise TargetValidationError("Enter a full domain name, for example example.com.")
        host = ascii_host

    netloc_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = netloc_host if port == default_port else f"{netloc_host}:{port}"
    path = parts.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    return ValidatedTarget(url=normalized, scheme=scheme, host=host, port=port)


def resolve_and_validate(host: str, port: int, config: ScanConfig) -> list[str]:
    """Resolve ``host`` and return its addresses only if *all* of them are permitted.

    Failing closed when any address is internal prevents round-robin rebinding tricks.
    """
    if port not in config.allowed_ports:
        raise BlockedDestinationError(f"port {port} is not permitted")
    literal = _parse_ip(host)
    if literal is not None:
        reason = ip_block_reason(literal, allow_private=config.allow_private_targets)
        if reason:
            raise BlockedDestinationError(reason)
        return [str(literal)]
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise httpcore.ConnectError(f"DNS resolution failed for {host}") from exc
    addresses: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        address = str(sockaddr[0])
        ip = _parse_ip(address)
        if ip is None:
            raise BlockedDestinationError("DNS returned an unparseable address")
        reason = ip_block_reason(ip, allow_private=config.allow_private_targets)
        if reason:
            raise BlockedDestinationError(f"{host} resolves to a blocked address ({reason})")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise httpcore.ConnectError(f"DNS returned no addresses for {host}")
    return addresses


class SafeNetworkBackend(httpcore.SyncBackend):
    """Connects only to addresses validated in the same step (no TOCTOU window)."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        addresses = resolve_and_validate(host, port, self._config)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return super().connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
        raise BlockedDestinationError("UNIX sockets are not permitted")


class SafeTransport(httpx.HTTPTransport):
    """httpx transport whose connection pool uses :class:`SafeNetworkBackend`."""

    def __init__(self, config: ScanConfig) -> None:
        super().__init__(retries=0)
        ssl_context = httpx.create_ssl_context()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=4,
            max_keepalive_connections=2,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=SafeNetworkBackend(config),
        )

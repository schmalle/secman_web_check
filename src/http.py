"""Bounded HTTP evidence collection with per-hop DNS policy and pinned dialing."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from time import monotonic
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpcore
import httpx
from httpcore._backends.base import SOCKET_OPTION, NetworkBackend, NetworkStream
from httpcore._backends.sync import SyncBackend

from .config import ScannerConfig
from .targets import (
    AddressDenied,
    AddressPolicy,
    NormalizedTarget,
    TargetError,
    normalize_target,
    resolve_allowed,
)

_REDIRECTS = {301, 302, 303, 307, 308}
_SAFE_HEADERS = {"accept", "accept-language", "origin", "cache-control", "pragma"}
_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


class CollectionError(RuntimeError):
    """A safe-to-report collection failure, without upstream exception details."""


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class HttpResponseEvidence:
    request: HttpRequest
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool
    elapsed_seconds: float
    redirect_url: str | None = None
    blocked_redirect_reason: str | None = None

    @property
    def url(self) -> str:
        return self.request.url


class PinnedNetworkBackend(NetworkBackend):
    """Substitute approved IP literals only; httpcore retains the TLS hostname."""

    def __init__(
        self,
        target: NormalizedTarget,
        addresses: tuple[str, ...],
        backend: NetworkBackend | None = None,
    ) -> None:
        self._host = target.host
        self._port = target.port or (443 if target.scheme == "https" else 80)
        # Literal-only inputs prevent the delegated backend from resolving a hostname.
        try:
            self._addresses = tuple(str(ipaddress.ip_address(address)) for address in addresses)
        except ValueError:
            raise AddressDenied("Pinned connection requires IP literals") from None
        if not self._addresses:
            raise AddressDenied("Pinned connection requires approved addresses")
        self._backend = backend if backend is not None else SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        if host != self._host or port != self._port or local_address is not None:
            raise AddressDenied("Connection does not match the approved target")
        deadline = None if timeout is None else monotonic() + timeout
        for address in self._addresses:
            remaining = None if deadline is None else max(0.0, deadline - monotonic())
            if remaining == 0:
                raise httpcore.ConnectTimeout("Approved connection timed out") from None
            try:
                return self._backend.connect_tcp(
                    address, port, timeout=remaining, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout):
                # Only a member of this already-validated DNS snapshot may be tried next.
                continue
        raise httpcore.ConnectError("Approved addresses could not be reached") from None

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        raise AddressDenied("Unix socket connections are not permitted")


class _PinnedTransport(httpx.HTTPTransport):
    def __init__(self, backend: PinnedNetworkBackend) -> None:
        # HTTPX 0.27's transport adapter uses this pool for request/response conversion.
        # Build it directly: no default backend, environment proxy, or unpinned fallback.
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            network_backend=backend,
        )


class _SingleHopClient(httpx.Client):
    def _build_redirect_request(
        self, request: httpx.Request, response: httpx.Response
    ) -> httpx.Request:
        # Even follow_redirects=False normally parses Location to build next_request.
        # Leave all redirect interpretation to the collector, including malformed URLs.
        return request


def _safe_url(value: str) -> str:
    try:
        target = normalize_target(value)
    except (TargetError, ValueError):
        return "<invalid URL>"
    parts = urlsplit(target.url)
    return urlunsplit(parts._replace(query="<redacted>" if parts.query else ""))


def _redirect_target(base_url: str, location: str) -> NormalizedTarget:
    # urljoin strips tabs/newlines before parsing; reject them before they disappear.
    if not location or any(char.isspace() or ord(char) < 32 for char in location):
        raise TargetError("Missing or invalid redirect location")
    return normalize_target(urljoin(base_url, location))


def _is_credential_header(name: str) -> bool:
    name = name.lower()
    return name in {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-amz-security-token",
        "authentication-info",
        "proxy-authentication-info",
    } or name.endswith(
        ("-api-key", "-auth-token", "-access-token", "-security-token", "-refresh-token")
    )


def _safe_headers(headers: httpx.Headers, base_url: str) -> tuple[tuple[str, str], ...]:
    result = []
    for name, value in headers.multi_items():
        if name == "set-cookie":
            first, separator, attributes = value.partition(";")
            cookie_name, equals, _ = first.partition("=")
            value = f"{cookie_name}=<redacted>" if equals else "<redacted>"
            if separator:
                value += separator + attributes
        elif _is_credential_header(name):
            value = "<redacted>"
        elif name == "location":
            try:
                value = _safe_url(_redirect_target(base_url, value).url)
            except ValueError:
                value = "<invalid URL>"
        result.append((name, value.replace("\r", "").replace("\n", "")))
    return tuple(result)


class HttpCollector:
    def __init__(
        self,
        config: ScannerConfig | None = None,
        *,
        resolver: Callable[..., object] = socket.getaddrinfo,
        network_backend: NetworkBackend | None = None,
    ) -> None:
        self.config = config if config is not None else ScannerConfig()
        self._policy = AddressPolicy.from_config(self.config)
        self._resolver = resolver
        self._network_backend = network_backend

    def with_max_body_bytes(self, max_body_bytes: int) -> HttpCollector:
        return HttpCollector(
            replace(self.config, max_body_bytes=max_body_bytes),
            resolver=self._resolver,
            network_backend=self._network_backend,
        )

    def collect(
        self,
        target: NormalizedTarget,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
    ) -> tuple[HttpResponseEvidence, ...]:
        method = method.upper()
        if method not in _METHODS:
            raise CollectionError("Request method is not permitted")
        safe_headers = {name.lower(): value for name, value in (headers or {}).items()}
        if set(safe_headers) - _SAFE_HEADERS:
            raise CollectionError("Request header is not permitted")
        if any(
            ord(char) < 32 or ord(char) > 126 for value in safe_headers.values() for char in value
        ):
            raise CollectionError("Request header value is invalid")
        safe_headers.update({"Accept-Encoding": "identity", "User-Agent": "secman-web-check/0.1"})
        results: list[HttpResponseEvidence] = []
        try:
            current = normalize_target(target.url)
            while True:
                addresses = resolve_allowed(current, self._policy, self._resolver)
                evidence, location = self._request(current, addresses, method, safe_headers)
                if evidence.status_code not in _REDIRECTS:
                    results.append(evidence)
                    return tuple(results)
                destination = None
                reason = None
                try:
                    if not location:
                        raise TargetError("Missing redirect location")
                    destination = _redirect_target(current.url, location)
                except (TargetError, ValueError):
                    reason = "Missing or invalid redirect location"
                if destination is not None:
                    if current.scheme == "https" and destination.scheme == "http":
                        reason = "HTTPS downgrade"
                    elif len(results) >= self.config.max_redirects:
                        reason = "Redirect limit reached"
                evidence = replace(
                    evidence,
                    redirect_url=None if destination is None else _safe_url(destination.url),
                    blocked_redirect_reason=reason,
                )
                results.append(evidence)
                if reason is not None or destination is None:
                    return tuple(results)
                current = destination
                if evidence.status_code == 303 and method != "HEAD":
                    method = "GET"
        except AddressDenied:
            raise AddressDenied("Target address denied by policy") from None
        except (httpx.HTTPError, OSError, ValueError):
            raise CollectionError("HTTP collection failed") from None

    def _request(
        self,
        target: NormalizedTarget,
        addresses: tuple[str, ...],
        method: str,
        headers: Mapping[str, str],
    ) -> tuple[HttpResponseEvidence, str | None]:
        backend = PinnedNetworkBackend(target, addresses, self._network_backend)
        timeout = httpx.Timeout(
            connect=self.config.connect_timeout_seconds,
            read=self.config.read_timeout_seconds,
            write=self.config.read_timeout_seconds,
            pool=self.config.connect_timeout_seconds,
        )
        started = monotonic()
        # A new client per hop prevents both cookie replay and connection reuse across DNS checks.
        with (
            _SingleHopClient(
                transport=_PinnedTransport(backend),
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                headers=headers,
            ) as client,
            client.stream(method, target.url) as response,
        ):
            if sum(len(name) + len(value) for name, value in response.headers.raw) > 65_536:
                raise CollectionError("Response headers exceed the size limit")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise CollectionError("Unsupported response encoding")
            body = bytearray()
            truncated = False
            for chunk in response.iter_raw():
                remaining = self.config.max_body_bytes - len(body)
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            locations = response.headers.get_list("location")
            location = locations[0] if len(locations) == 1 else None
            return HttpResponseEvidence(
                request=HttpRequest(
                    method=method,
                    url=_safe_url(target.url),
                    headers=_safe_headers(response.request.headers, target.url),
                ),
                status_code=response.status_code,
                headers=_safe_headers(response.headers, target.url),
                body=bytes(body),
                truncated=truncated,
                elapsed_seconds=monotonic() - started,
            ), location

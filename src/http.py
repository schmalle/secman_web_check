"""Bounded HTTP evidence collection with per-hop DNS policy and pinned dialing."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from time import monotonic, sleep
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


class RequestBudget:
    """Count every HTTP hop and pace requests by origin across a target scan."""

    def __init__(self, max_requests: int, requests_per_second: float) -> None:
        if max_requests < 1 or requests_per_second <= 0:
            raise ValueError("Request budget limits must be positive")
        self.max_requests = max_requests
        self.requests_per_second = requests_per_second
        self._count = 0
        self._next_by_origin: dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def claim(self, target: NormalizedTarget, deadline: float | None = None) -> None:
        authority = f"[{target.host}]" if ":" in target.host else target.host
        if target.port is not None:
            authority += f":{target.port}"
        key = f"{target.scheme}://{authority}"
        with self._lock:
            if self._count >= self.max_requests:
                raise CollectionError("HTTP request budget reached")
            now = monotonic()
            scheduled = max(now, self._next_by_origin.get(key, now))
            self._next_by_origin[key] = scheduled + 1.0 / self.requests_per_second
            self._count += 1
        remaining = scheduled - monotonic()
        if deadline is not None and scheduled >= deadline:
            raise CollectionError("HTTP deadline exceeded during request pacing")
        if remaining > 0:
            sleep(remaining)


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
        deadline: float | None = None,
    ) -> None:
        self._deadline = deadline
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
        if self._deadline is not None:
            deadline = min(deadline, self._deadline) if deadline is not None else self._deadline
        for address in self._addresses:
            remaining = None if deadline is None else max(0.0, deadline - monotonic())
            if remaining == 0:
                raise httpcore.ConnectTimeout("Approved connection timed out") from None
            try:
                stream = self._backend.connect_tcp(
                    address, port, timeout=remaining, socket_options=socket_options
                )
                return (
                    _DeadlineStream(stream, self._deadline)
                    if self._deadline is not None
                    else stream
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


class _DeadlineStream(NetworkStream):
    """Bound all socket operations, including header reads, by one monotonic deadline."""

    def __init__(self, stream: NetworkStream, deadline: float) -> None:
        self.stream = stream
        self.deadline = deadline

    def _remaining(self, timeout: float | None) -> float:
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise httpcore.ReadTimeout("HTTP deadline exceeded")
        return min(timeout, remaining) if timeout is not None else remaining

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        result = self.stream.read(max_bytes, timeout=self._remaining(timeout))
        self._remaining(timeout)
        return result

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.stream.write(buffer, timeout=self._remaining(timeout))
        self._remaining(timeout)

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> NetworkStream:
        stream = self.stream.start_tls(
            ssl_context, server_hostname, timeout=self._remaining(timeout)
        )
        self.stream = stream
        self._remaining(timeout)
        return self

    def close(self) -> None:
        self.stream.close()

    def get_extra_info(self, info: str) -> object:
        return self.stream.get_extra_info(info)


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


def pinned_transport(target: NormalizedTarget, addresses: tuple[str, ...]) -> httpx.HTTPTransport:
    """Build a verified synchronous transport that can dial only approved IP literals."""
    return _PinnedTransport(PinnedNetworkBackend(target, addresses))


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
        allowed_origins: frozenset[str] | None = None,
        budget: RequestBudget | None = None,
        deadline: float | None = None,
    ) -> None:
        self.config = config if config is not None else ScannerConfig()
        self._policy = AddressPolicy.from_config(self.config)
        self._resolver = resolver
        self._network_backend = network_backend
        self._allowed_origins = allowed_origins
        self._budget = budget
        self._deadline = deadline

    def with_deadline(self, deadline: float) -> HttpCollector:
        return HttpCollector(
            self.config,
            resolver=self._resolver,
            network_backend=self._network_backend,
            allowed_origins=self._allowed_origins,
            budget=self._budget,
            deadline=min(deadline, self._deadline) if self._deadline else deadline,
        )

    @property
    def request_count(self) -> int:
        return self._budget.count if self._budget is not None else 0

    def with_budget(self, budget: RequestBudget) -> HttpCollector:
        return HttpCollector(
            self.config,
            resolver=self._resolver,
            network_backend=self._network_backend,
            allowed_origins=self._allowed_origins,
            budget=budget,
            deadline=self._deadline,
        )

    def with_max_body_bytes(self, max_body_bytes: int) -> HttpCollector:
        return HttpCollector(
            replace(self.config, max_body_bytes=max_body_bytes),
            resolver=self._resolver,
            network_backend=self._network_backend,
            allowed_origins=self._allowed_origins,
            budget=self._budget,
            deadline=self._deadline,
        )

    def with_max_redirects(self, max_redirects: int) -> HttpCollector:
        return HttpCollector(
            replace(self.config, max_redirects=max_redirects),
            resolver=self._resolver,
            network_backend=self._network_backend,
            allowed_origins=self._allowed_origins,
            budget=self._budget,
            deadline=self._deadline,
        )

    def with_allowed_origins(self, allowed_origins: frozenset[str]) -> HttpCollector:
        return HttpCollector(
            self.config,
            resolver=self._resolver,
            network_backend=self._network_backend,
            allowed_origins=allowed_origins,
            budget=self._budget,
            deadline=self._deadline,
        )

    def _check_origin(self, target: NormalizedTarget) -> None:
        if self._allowed_origins is None:
            return
        authority = f"[{target.host}]" if ":" in target.host else target.host
        if target.port is not None:
            authority += f":{target.port}"
        if f"{target.scheme}://{authority}" not in self._allowed_origins:
            raise AddressDenied("Target origin denied by policy")

    def collect_one(
        self, target: NormalizedTarget, method: str = "GET"
    ) -> tuple[HttpResponseEvidence, str | None]:
        """Fetch one pinned hop for browser interception; validate a redirect before release."""
        if method not in {"GET", "HEAD"}:
            raise CollectionError("Browser request method is not permitted")
        deadline = min(
            monotonic() + self.config.request_timeout_seconds, self._deadline or float("inf")
        )
        try:
            current = normalize_target(target.url)
            self._check_origin(current)
            addresses = resolve_allowed(current, self._policy, self._resolver)
            if self._budget is not None:
                self._budget.claim(current, deadline)
            evidence, location = self._request(
                current,
                addresses,
                method,
                {"Accept-Encoding": "identity", "User-Agent": "secman-web-check/0.1"},
                deadline,
            )
            if evidence.truncated:
                raise CollectionError("Browser response exceeded the size limit")
            if evidence.status_code not in _REDIRECTS:
                return evidence, None
            if not location:
                raise CollectionError("Browser redirect is missing or ambiguous")
            destination = _redirect_target(current.url, location)
            self._check_origin(destination)
            if current.scheme == "https" and destination.scheme == "http":
                raise CollectionError("Browser redirect downgraded to HTTP")
            resolve_allowed(destination, self._policy, self._resolver)
            return evidence, destination.url
        except (AddressDenied, TargetError, httpx.HTTPError, OSError, ValueError):
            raise CollectionError("Browser request denied or failed") from None

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
        deadline = min(
            monotonic() + self.config.request_timeout_seconds, self._deadline or float("inf")
        )
        try:
            current = normalize_target(target.url)
            while True:
                self._check_origin(current)
                addresses = resolve_allowed(current, self._policy, self._resolver)
                if self._budget is not None:
                    self._budget.claim(current, deadline)
                evidence, location = self._request(
                    current, addresses, method, safe_headers, deadline
                )
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
                    elif self._allowed_origins is not None:
                        try:
                            self._check_origin(destination)
                        except AddressDenied:
                            reason = "Redirect origin denied by policy"
                    if reason is None and len(results) >= self.config.max_redirects:
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
        deadline: float | None = None,
    ) -> tuple[HttpResponseEvidence, str | None]:
        deadline = min(
            deadline or monotonic() + self.config.request_timeout_seconds,
            self._deadline or float("inf"),
        )
        if monotonic() >= deadline:
            raise CollectionError("HTTP deadline exceeded")
        backend = PinnedNetworkBackend(target, addresses, self._network_backend, deadline)
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

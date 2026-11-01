"""Explicit-origin proxy for sandboxed external engines; no DNS or egress in children."""

from __future__ import annotations

import select
import socket
import socketserver
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from threading import Thread
from time import monotonic
from urllib.parse import urlsplit

from .http import target_origin
from .targets import AddressPolicy, NormalizedTarget, normalize_target, resolve_allowed
from .traffic import TrafficController


class _Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(
        self,
        target: NormalizedTarget,
        policy: AddressPolicy,
        traffic: TrafficController | None,
        deadline: float,
    ) -> None:
        self.target = target
        self.policy = policy
        self.traffic = traffic
        self.deadline = deadline
        super().__init__(("127.0.0.1", 0), _Handler)


class _Handler(socketserver.BaseRequestHandler):
    server: _Proxy
    request: socket.socket

    def handle(self) -> None:
        self.request.settimeout(2.0)
        try:
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                part = self.request.recv(1)
                if not part or len(head) >= 16384 or monotonic() >= self.server.deadline:
                    return
                head.extend(part)
            line, *headers = head.decode("ascii").split("\r\n")
            method, location, version = line.split(" ")
            target = self.server.target
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                raise ValueError("invalid proxy request")
            if method == "CONNECT":
                requested = normalize_target("https://" + location)
                if target.scheme != "https":
                    raise ValueError("tunnel denied")
            elif method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
                requested = normalize_target(location)
                if target.scheme != "http":
                    raise ValueError("request denied")
            else:
                raise ValueError("method denied")
            if target_origin(requested) != target_origin(target):
                raise ValueError("proxy origin denied")
            # Every new connection resolves and validates all answers; only an approved
            # IP literal reaches the socket. CONNECT retains tool-controlled Host/SNI.
            address = resolve_allowed(target, self.server.policy)[0]
            gate = (
                self.server.traffic.admit(target_origin(target), "external", self.server.deadline)
                if self.server.traffic
                else nullcontext()
            )
            with (
                gate,
                socket.create_connection(
                    (address, target.port or (443 if target.scheme == "https" else 80)), timeout=5
                ) as upstream,
            ):
                if method == "CONNECT":
                    self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    parts = urlsplit(requested.url)
                    path = parts.path or "/"
                    if parts.query:
                        path += "?" + parts.query
                    # No credentials, upgrade, proxy headers or connection reuse.
                    safe = [
                        h
                        for h in headers
                        if h and h.split(":", 1)[0].lower() in {"accept", "user-agent", "origin"}
                    ]
                    authority = urlsplit(target.url).netloc
                    request = (
                        f"{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
                        + "\r\n".join(safe)
                        + "\r\n\r\n"
                    )
                    upstream.sendall(request.encode("ascii"))
                transferred = 0
                while monotonic() < self.server.deadline and transferred < 8_000_000:
                    ready, _, _ = select.select([self.request, upstream], [], [], 0.1)
                    for source in ready:
                        chunk = source.recv(16384)
                        if not chunk:
                            return
                        transferred += len(chunk)
                        destination = upstream if source is self.request else self.request
                        destination.sendall(chunk)
        except (OSError, ValueError, UnicodeError):
            try:
                self.request.sendall(
                    b"HTTP/1.1 403 Scope denied\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass


@contextmanager
def scoped_proxy(
    target: NormalizedTarget,
    policy: AddressPolicy,
    traffic: TrafficController | None,
    timeout: float,
) -> Iterator[int]:
    with _Proxy(target, policy, traffic, monotonic() + timeout) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield int(server.server_address[1])
        finally:
            server.shutdown()
            thread.join(timeout=2)

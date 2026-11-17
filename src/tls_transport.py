"""Narrow SSLyze 6.x connection hook: validate and lease every actual TCP socket."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic
from typing import Any

from .config import ScannerConfig
from .http import target_origin
from .targets import AddressDenied, AddressPolicy, NormalizedTarget, resolve_allowed
from .traffic import TrafficController, TrafficDenied

_PATCH_LOCK = threading.Lock()


class TlsConnectionDenied(OSError):
    """A refused TLS socket, typed as OSError so SSLyze records a failed connection.

    SSLyze's worker threads catch only socket errors; any other exception kills the
    thread, prints a traceback and leaves the scan waiting until the target deadline.
    """


class _LeasedSocket(socket.socket):
    def __init__(self, raw: socket.socket, lease: Any) -> None:
        family, kind, protocol, timeout = raw.family, raw.type, raw.proto, raw.gettimeout()
        super().__init__(family, kind, protocol, fileno=raw.detach())
        self.settimeout(timeout)
        self._lease = lease

    def close(self) -> None:
        try:
            super().close()
        finally:
            lease = getattr(self, "_lease", None)
            if lease is not None:
                self._lease = None
                lease.__exit__(None, None, None)


@contextmanager
def tls_connections(
    target: NormalizedTarget, config: ScannerConfig, traffic: TrafficController | None
) -> Iterator[None]:
    from sslyze.connection_helpers import tls_connection

    controller = traffic or TrafficController(config)
    deadline = monotonic() + config.target_timeout_seconds

    def connect(server_location: Any, network_timeout: int) -> socket.socket:
        location = server_location
        try:
            addresses = resolve_allowed(target, AddressPolicy.from_config(config))
        except AddressDenied:
            raise TlsConnectionDenied("TLS target resolved to a denied address") from None
        if (
            location.ip_address not in addresses
            or location.port != (target.port or 443)
            or location.hostname != target.host
        ):
            raise TlsConnectionDenied("TLS connection no longer matches approved DNS snapshot")
        lease = controller.admit(target_origin(target), "tls", deadline)
        try:
            lease.__enter__()
        except TrafficDenied as error:
            raise TlsConnectionDenied(str(error)) from None
        try:
            raw = socket.create_connection(
                (location.ip_address, location.port),
                timeout=min(network_timeout, max(0.001, deadline - monotonic())),
            )
            return _LeasedSocket(raw, lease)
        except BaseException:
            lease.__exit__(None, None, None)
            raise

    # SSLyze starts threads; patch only its dedicated direct-connect helper in this
    # isolated target process, never Python's global socket module.
    with _PATCH_LOCK:
        original = tls_connection._open_socket_for_direct_connection
        tls_connection._open_socket_for_direct_connection = connect
        try:
            yield
        finally:
            tls_connection._open_socket_for_direct_connection = original

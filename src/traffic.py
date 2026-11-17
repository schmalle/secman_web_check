"""Run-wide admission shared by spawned workers, browser threads and provider calls."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from multiprocessing.managers import SyncManager
from time import monotonic, sleep
from typing import Any
from uuid import uuid4

from .config import ScannerConfig


class TrafficDenied(ValueError):
    """Cancelled, exhausted or expired run admission; safe for public errors."""


_WAIT = "\0wait"


class _Ledger:
    """Admission state. Each method is atomic and runs in one thread of the manager.

    The lock is only ever held inside a single call, so a worker killed mid-call cannot
    leave it held, which a lock acquired and released by separate client calls could.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {}
        self._leases: dict[str, tuple[int, str, str, float]] = {}

    def try_admit(
        self, key: str, pid: int, origin: str, engine: str, deadline: float
    ) -> str | None:
        """Return None when admitted, ``_WAIT`` to retry, or a public denial message."""
        config = self._config
        now = monotonic()
        with self._lock:
            state = self._state
            if state.get("cancelled", False):
                return "Run cancelled"
            if now >= deadline:
                return "Traffic admission deadline exceeded"
            for name, value in list(self._leases.items()):
                if value[3] <= now:
                    del self._leases[name]
            count = int(state.get("operations", 0))
            if count >= config.max_operations:
                return "Run operation budget exhausted"
            if engine == "provider" and int(state.get("provider", 0)) >= config.max_provider_calls:
                return "Provider call budget exhausted"
            # TLS handshakes are paced apart from HTTP requests to the same origin.
            pace_key, origin_rate = (
                ("next:tls:" + origin, config.tls_connections_per_second)
                if engine == "tls"
                else ("next:" + origin, config.requests_per_second)
            )
            scheduled = max(float(state.get("next", 0.0)), float(state.get(pace_key, 0.0)))
            if (
                len(self._leases) < config.concurrency
                and sum(value[1] == origin for value in self._leases.values())
                < config.per_origin_concurrency
                and now >= scheduled
            ):
                self._leases[key] = (pid, origin, engine, deadline)
                state["next"] = now + 1.0 / config.global_requests_per_second
                state[pace_key] = now + 1.0 / origin_rate
                state["operations"] = count + 1
                state[engine] = int(state.get(engine, 0)) + 1
                state["peak"] = max(int(state.get("peak", 0)), len(self._leases))
                return None
        return _WAIT

    def release(self, key: str) -> None:
        with self._lock:
            self._leases.pop(key, None)

    def release_owner(self, pid: int) -> None:
        with self._lock:
            for key, value in list(self._leases.items()):
                if value[0] == pid:
                    del self._leases[key]

    def lease_count(self) -> int:
        with self._lock:
            return len(self._leases)

    def cancel(self) -> None:
        with self._lock:
            self._state["cancelled"] = True

    def cancelled(self) -> bool:
        with self._lock:
            return bool(self._state.get("cancelled", False))

    def metrics(self) -> dict[str, int]:
        with self._lock:
            return {
                key: int(self._state.get(key, 0))
                for key in ("operations", "http", "tls", "provider", "external", "peak")
            }


class _TrafficManager(SyncManager):
    pass


_TrafficManager.register("Ledger", _Ledger)


class TrafficController:
    def __init__(self, config: ScannerConfig, ledger: Any = None) -> None:
        self.config = config
        self.ledger: Any = _Ledger(config) if ledger is None else ledger

    @contextmanager
    def admit(self, origin: str, engine: str, deadline: float | None = None) -> Iterator[None]:
        deadline = deadline or monotonic() + self.config.target_timeout_seconds
        key = "lease:" + uuid4().hex
        while True:
            verdict = self.ledger.try_admit(key, os.getpid(), origin, engine, deadline)
            if verdict is None:
                break
            if verdict != _WAIT:
                raise TrafficDenied(verdict)
            sleep(min(0.05, max(0.001, deadline - monotonic())))
        try:
            yield
        finally:
            self.ledger.release(key)

    def release_owner(self, pid: int) -> None:
        """Reclaim leases of a worker killed while inside an adapter."""
        self.ledger.release_owner(pid)

    @property
    def cancelled(self) -> bool:
        return bool(self.ledger.cancelled())

    def cancel(self) -> None:
        self.ledger.cancel()

    def metrics(self) -> dict[str, int]:
        return dict(self.ledger.metrics())


@contextmanager
def traffic_run(config: ScannerConfig) -> Iterator[TrafficController]:
    with _TrafficManager() as manager:
        ledger: Any = getattr(manager, "Ledger")(config)  # noqa: B009 - registered at import
        controller = TrafficController(config, ledger)
        try:
            yield controller
        finally:
            controller.cancel()

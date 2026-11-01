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


class TrafficController:
    def __init__(
        self, config: ScannerConfig, state: Any = None, lock: Any = None, leases: Any = None
    ) -> None:
        self.config = config
        self.state: Any = {} if state is None else state
        self.lock: Any = threading.RLock() if lock is None else lock
        self.leases: Any = {} if leases is None else leases

    @contextmanager
    def admit(self, origin: str, engine: str, deadline: float | None = None) -> Iterator[None]:
        deadline = deadline or monotonic() + self.config.target_timeout_seconds
        key = "lease:" + uuid4().hex
        while True:
            now = monotonic()
            with self.lock:
                if self.state.get("cancelled", False):
                    raise TrafficDenied("Run cancelled")
                if now >= deadline:
                    raise TrafficDenied("Traffic admission deadline exceeded")
                leases = []
                for name, value in list(self.leases.items()):
                    if value[3] <= now:
                        del self.leases[name]
                    else:
                        leases.append(value)
                count = int(self.state.get("operations", 0))
                if count >= self.config.max_operations:
                    raise TrafficDenied("Run operation budget exhausted")
                if (
                    engine == "provider"
                    and int(self.state.get("provider", 0)) >= self.config.max_provider_calls
                ):
                    raise TrafficDenied("Provider call budget exhausted")
                scheduled = max(
                    float(self.state.get("next", 0.0)), float(self.state.get("next:" + origin, 0.0))
                )
                if (
                    len(leases) < self.config.concurrency
                    and sum(value[1] == origin for value in leases)
                    < self.config.per_origin_concurrency
                    and now >= scheduled
                ):
                    self.leases[key] = (os.getpid(), origin, engine, deadline)
                    self.state["next"] = now + 1.0 / self.config.global_requests_per_second
                    self.state["next:" + origin] = now + 1.0 / self.config.requests_per_second
                    self.state["operations"] = count + 1
                    self.state[engine] = int(self.state.get(engine, 0)) + 1
                    self.state["peak"] = max(int(self.state.get("peak", 0)), len(leases) + 1)
                    break
            sleep(min(0.05, max(0.001, deadline - monotonic())))
        try:
            yield
        finally:
            with self.lock:
                self.leases.pop(key, None)

    def release_owner(self, pid: int) -> None:
        """Reclaim leases of a worker killed while inside an adapter."""
        with self.lock:
            for key, value in list(self.leases.items()):
                if value[0] == pid:
                    del self.leases[key]

    @property
    def cancelled(self) -> bool:
        return bool(self.state.get("cancelled", False))

    def cancel(self) -> None:
        with self.lock:
            self.state["cancelled"] = True

    def metrics(self) -> dict[str, int]:
        with self.lock:
            return {
                key: int(self.state.get(key, 0))
                for key in ("operations", "http", "tls", "provider", "external", "peak")
            }


@contextmanager
def traffic_run(config: ScannerConfig) -> Iterator[TrafficController]:
    with SyncManager() as manager:
        controller = TrafficController(config, manager.dict(), manager.RLock(), manager.dict())
        try:
            yield controller
        finally:
            controller.cancel()

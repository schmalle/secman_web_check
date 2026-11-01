import multiprocessing
import os
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import pairwise

import pytest

from secman_web_check.config import ScannerConfig
from secman_web_check.traffic import TrafficController, TrafficDenied, traffic_run


def _admission_worker(controller, queue, origin):
    with controller.admit(origin, "http"):
        queue.put(("start", time.monotonic(), os.getpid()))
        time.sleep(0.04)
        queue.put(("end", time.monotonic(), os.getpid()))


def test_spawned_workers_share_pacing_and_origin_connection_limit():
    config = ScannerConfig(
        concurrency=3,
        requests_per_second=10,
        global_requests_per_second=100,
        per_origin_concurrency=1,
    )
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    with traffic_run(config) as controller:
        processes = [
            context.Process(
                target=_admission_worker, args=(controller, queue, "https://fixture.example:443")
            )
            for _ in range(3)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        events = [queue.get(timeout=2) for _ in range(6)]
        starts = sorted(stamp for kind, stamp, _ in events if kind == "start")
        assert all(right - left >= 0.09 for left, right in pairwise(starts))
        ordered = sorted(events, key=lambda event: event[1])
        active = peak = 0
        for kind, _, _ in ordered:
            active += 1 if kind == "start" else -1
            peak = max(peak, active)
        assert peak == 1
        assert controller.metrics()["http"] == 3
    queue.close()


def test_budget_cancellation_deadline_and_provider_caps_are_shared():
    config = ScannerConfig(
        requests_per_second=1000,
        global_requests_per_second=1000,
        max_operations=2,
        max_provider_calls=1,
    )
    controller = TrafficController(config)
    with controller.admit("https://provider.example:443", "provider"):
        pass
    with (
        pytest.raises(TrafficDenied, match="Provider call budget"),
        controller.admit("https://provider.example:443", "provider"),
    ):
        pass
    with controller.admit("https://fixture.example:443", "tls"):
        pass
    with (
        pytest.raises(TrafficDenied, match="operation budget"),
        controller.admit("https://fixture.example:443", "external"),
    ):
        pass
    controller.cancel()
    with (
        pytest.raises(TrafficDenied, match="cancelled"),
        controller.admit("https://fixture.example:443", "http"),
    ):
        pass
    with (
        pytest.raises(TrafficDenied, match="deadline"),
        TrafficController(ScannerConfig()).admit("fixture", "http", time.monotonic() - 1),
    ):
        pass


def test_distinct_origins_share_global_connection_ceiling_and_dead_worker_leases_reclaim():
    config = ScannerConfig(concurrency=1, requests_per_second=1000, global_requests_per_second=1000)
    controller = TrafficController(config)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(_admit, controller, origin)
            for origin in ("https://one.example:443", "https://two.example:443")
        ]
        for future in futures:
            future.result(timeout=2)
    assert controller.metrics()["peak"] == 1
    controller.leases["lease:dead"] = (999999, "fixture", "external", time.monotonic() + 100)
    controller.release_owner(999999)
    assert "lease:dead" not in controller.leases


def _admit(controller, origin):
    with controller.admit(origin, "http"):
        time.sleep(0.02)

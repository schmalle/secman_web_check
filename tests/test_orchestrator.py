from datetime import UTC, datetime

import pytest

from secman_web_check.agent import AgentOptions
from secman_web_check.config import ScannerConfig
from secman_web_check.crawler import CrawlOptions
from secman_web_check.http import CollectionError, HttpRequest, HttpResponseEvidence
from secman_web_check.models import Reachability, TargetResult, TargetStatus
from secman_web_check.orchestrator import scan_all, scan_target
from secman_web_check.targets import normalize_target
from secman_web_check.tls import TlsEvidence


def test_batch_preserves_input_order_and_isolates_failure(monkeypatch):
    targets = (normalize_target("https://bad.example"), normalize_target("https://good.example"))

    def fake_scan(target, _config, **_options):
        if target.host == "bad.example":
            raise RuntimeError("secret upstream detail")
        now = datetime.now(UTC)
        return TargetResult(target, TargetStatus.SUCCESS, started_at=now, completed_at=now)

    monkeypatch.setattr("secman_web_check.orchestrator._bounded_scan_target", fake_scan)
    run = scan_all(targets, ScannerConfig(concurrency=2))
    assert [result.target.host for result in run.targets] == ["bad.example", "good.example"]
    assert [result.status for result in run.targets] == [TargetStatus.FAILED, TargetStatus.SUCCESS]
    assert "secret" not in repr(run)


def test_progress_callback_reports_every_target_once_including_failures(monkeypatch):
    targets = (
        normalize_target("https://bad.example"),
        normalize_target("https://good.example"),
        normalize_target("https://also-good.example"),
    )

    def fake_scan(target, _config, **_options):
        if target.host == "bad.example":
            raise RuntimeError("boom")
        now = datetime.now(UTC)
        return TargetResult(target, TargetStatus.SUCCESS, started_at=now, completed_at=now)

    monkeypatch.setattr("secman_web_check.orchestrator._bounded_scan_target", fake_scan)
    events = []
    run = scan_all(
        targets,
        ScannerConfig(concurrency=2),
        progress=lambda completed, total, result: events.append((completed, total, result)),
    )
    assert [completed for completed, _total, _result in events] == [1, 2, 3]
    assert {total for _completed, total, _result in events} == {3}
    assert {result.target.host for _completed, _total, result in events} == {
        "bad.example",
        "good.example",
        "also-good.example",
    }
    assert {result.status for _completed, _total, result in events} == {
        TargetStatus.FAILED,
        TargetStatus.SUCCESS,
    }
    assert len(run.targets) == 3


class FakeCollector:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status

    def with_max_body_bytes(self, _max_body_bytes):
        return self

    def collect(self, target, method="GET", headers=None):
        return (
            HttpResponseEvidence(
                request=HttpRequest("GET", target.url),
                status_code=self.status,
                headers=(),
                body=self.body,
                truncated=False,
                elapsed_seconds=0.0,
            ),
        )


class FakeTlsScanner:
    def scan(self, _target):
        return TlsEvidence(True), ()


def run_scan(body, status=200):
    return scan_target(
        normalize_target("https://api.example.com/prod"),
        ScannerConfig(),
        collector=FakeCollector(body, status),
        tls_scanner=FakeTlsScanner(),
    )


def test_api_gateway_marker_url_is_noted_as_authenticated():
    body = b'{"message":"Missing Authentication Token"}'
    result = run_scan(body, status=403)
    assert result.exposure.reachability is Reachability.AUTHENTICATED
    assert result.exposure.http_status == 403
    assert result.exposure.body_length == len(body)


@pytest.mark.parametrize(
    "body",
    [
        b'{"message":"Missing Authentication Token"}\n',
        b'  {"message":"Missing Authentication Token"}  ',
    ],
)
def test_marker_match_ignores_surrounding_whitespace(body):
    assert run_scan(body, status=403).exposure.reachability is Reachability.AUTHENTICATED


@pytest.mark.parametrize(
    "body",
    [
        b'{"message":"Missing Authentication Token","extra":1}',
        b'{"Message":"Missing Authentication Token"}',
        b'{ "message": "Missing Authentication Token" }',
        b"ok",
    ],
)
def test_non_exact_bodies_stay_reachable_and_record_body_length(body):
    result = run_scan(body)
    assert result.exposure.reachability is Reachability.REACHABLE
    assert result.exposure.body_length == len(body)


def test_failed_collection_has_unknown_reachability_and_no_body_length():
    class FailingCollector:
        def collect(self, target, method="GET", headers=None):
            raise CollectionError("HTTP collection failed")

    result = scan_target(
        normalize_target("https://down.example"),
        ScannerConfig(),
        collector=FailingCollector(),
        tls_scanner=FakeTlsScanner(),
    )
    assert result.status is TargetStatus.FAILED
    assert result.exposure.reachability is Reachability.UNKNOWN
    assert result.exposure.body_length is None


def test_crawl_budget_marks_target_partial_and_inventory_incomplete():
    class CrawlCollector:
        def with_allowed_origins(self, _origins):
            return self

        def with_max_body_bytes(self, _limit):
            return self

        def with_max_redirects(self, _limit):
            return self

        def collect(self, target, method="GET", headers=None):
            body = b'<a href="/one">one</a><a href="/two">two</a>'
            if target.url.endswith("security.txt"):
                return (
                    HttpResponseEvidence(HttpRequest("GET", target.url), 404, (), b"", False, 0.01),
                )
            return (
                HttpResponseEvidence(
                    HttpRequest("GET", target.url),
                    200,
                    (("content-type", "text/html"),),
                    body if target.url.endswith("/") else b"",
                    False,
                    0.01,
                ),
            )

    result = scan_target(
        normalize_target("https://example.com/"),
        ScannerConfig(),
        collector=CrawlCollector(),
        tls_scanner=FakeTlsScanner(),
        crawl_options=CrawlOptions(max_pages=2),
    )

    assert result.status is TargetStatus.PARTIAL
    assert not result.complete
    assert not result.inventory_complete
    assert result.coverage.pages_scanned == 2
    assert result.coverage.pages == ("https://example.com/", "https://example.com/one")


def test_cross_origin_redirect_skips_optional_probes(monkeypatch):
    class RedirectCollector:
        def with_max_body_bytes(self, _limit):
            return self

        def collect(self, target, method="GET", headers=None):
            url = (
                target.url
                if target.url.endswith("security.txt")
                else "https://destination.example/"
            )
            return (HttpResponseEvidence(HttpRequest("GET", url), 200, (), b"", False, 0.01),)

    def unexpected(*_args, **_kwargs):
        raise AssertionError("optional probe crossed redirect boundary")

    monkeypatch.setattr("secman_web_check.orchestrator.discover_paths", unexpected)
    monkeypatch.setattr("secman_web_check.orchestrator.scan_with_external", unexpected)
    monkeypatch.setattr("secman_web_check.orchestrator.run_agent", unexpected)
    result = scan_target(
        normalize_target("https://source.example/"),
        ScannerConfig(active=True),
        collector=RedirectCollector(),
        tls_scanner=FakeTlsScanner(),
        dirbuster=True,
        external_scanners=("nuclei",),
        agent_options=AgentOptions("test-key", "test-model"),
    )

    assert result.status is TargetStatus.PARTIAL
    assert "Optional probes skipped after cross-origin redirect" in result.errors
    assert not result.coverage.agent_complete


def test_outer_target_deadline_terminates_worker_before_scan_can_stall():
    from time import monotonic

    from secman_web_check.orchestrator import _bounded_scan_target

    started = monotonic()
    result = _bounded_scan_target(
        normalize_target("https://example.com"), ScannerConfig(target_timeout_seconds=0.001)
    )
    assert monotonic() - started < 3
    assert result.status == TargetStatus.FAILED
    assert not result.complete
    assert result.errors == ("Target deadline exceeded",)


def test_outer_target_worker_preserves_sanitized_denied_target_result():
    from secman_web_check.orchestrator import _bounded_scan_target

    result = _bounded_scan_target(normalize_target("http://127.0.0.1"), ScannerConfig())
    assert result.status == TargetStatus.FAILED
    assert not result.complete
    assert "address was denied" in result.errors[0]

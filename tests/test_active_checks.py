from types import SimpleNamespace

from secman_web_check.checks.active import run_active_checks
from secman_web_check.checks.registry import CheckContext
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def evidence(url="https://example.com/", body=b"ok"):
    return HttpResponseEvidence(HttpRequest("GET", url), 200, (), body, False, 0.01)


class RecordingCollector:
    def __init__(self):
        self.requests = []

    def with_max_body_bytes(self, _limit):
        return self

    def collect(self, target, method="GET", headers=None):
        self.requests.append(SimpleNamespace(target=target, method=method, headers=headers))
        return (evidence(target.url),)


def test_active_checks_make_no_requests_when_disabled():
    collector = RecordingCollector()
    assert run_active_checks(CheckContext(evidence()), collector, enabled=False).findings == ()
    assert collector.requests == []


def test_active_checks_use_only_fixed_catalogue_requests():
    collector = RecordingCollector()
    run_active_checks(CheckContext(evidence()), collector, enabled=True)
    assert {(request.method, request.target.url) for request in collector.requests} == {
        ("TRACE", "https://example.com/"),
        ("OPTIONS", "https://example.com/"),
        ("GET", "https://example.com/.env"),
        ("GET", "https://example.com/.git/HEAD"),
        ("GET", "https://example.com/server-status"),
        ("GET", "https://example.com/wp-config.php.bak"),
    }

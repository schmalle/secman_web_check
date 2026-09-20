from secman_web_check.discovery import discover_paths
from secman_web_check.http import HttpRequest, HttpResponseEvidence
from secman_web_check.targets import normalize_target


class Collector:
    def with_max_body_bytes(self, _limit):
        return self

    def collect(self, target):
        status = 200 if target.url.endswith("/admin/") else 404
        return (HttpResponseEvidence(HttpRequest("GET", target.url), status, (), b"", False, 0.1),)


def test_bounded_discovery_reports_only_non_missing_paths():
    result = discover_paths(
        normalize_target("https://example.com/app"), Collector(), paths=("admin/", "missing/")
    )

    assert len(result.findings) == 1
    assert result.findings[0].engine == "secman-web-check-dirbuster"
    assert result.findings[0].url == "https://example.com/admin/"


def test_discovery_rejects_unsafe_custom_path():
    try:
        discover_paths(normalize_target("https://example.com"), Collector(), paths=("../secret",))
    except ValueError as error:
        assert "safe relative paths" in str(error)
    else:
        raise AssertionError("unsafe path was accepted")

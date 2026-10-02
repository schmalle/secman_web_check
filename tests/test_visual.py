from __future__ import annotations

import asyncio
import base64
import ipaddress

import pytest

from secman_web_check.models import Severity
from secman_web_check.targets import AddressPolicy, normalize_target
from secman_web_check.visual import (
    PageCapture,
    VisualOptions,
    _analyze,
    _parse_analysis,
    _route_handler,
    scan_visual_all,
)


class FakeRequest:
    resource_type = "document"

    def __init__(self, url: str) -> None:
        self.url = url


class FakeRoute:
    def __init__(self, url: str) -> None:
        self.request = FakeRequest(url)
        self.outcome = ""
        self.fulfilled = None

    async def abort(self) -> None:
        self.outcome = "aborted"

    async def continue_(self) -> None:
        self.outcome = "continued"

    async def fulfill(self, **kwargs) -> None:
        self.outcome = "fulfilled"
        self.fulfilled = kwargs


def test_browser_route_blocks_denied_network_destination(monkeypatch) -> None:
    monkeypatch.setattr(
        "secman_web_check.visual.resolve_allowed",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("denied")),
    )
    route = FakeRoute("http://169.254.169.254/latest/meta-data")

    asyncio.run(_route_handler(AddressPolicy())(route))

    assert route.outcome == "aborted"


def test_browser_route_uses_pinned_collector_instead_of_browser_network() -> None:
    from secman_web_check.http import HttpRequest, HttpResponseEvidence

    class Collector:
        def collect_one(self, target, method):
            assert target.url == "https://example.com/"
            assert method == "GET"
            return (
                HttpResponseEvidence(
                    request=HttpRequest("GET", target.url),
                    status_code=200,
                    headers=(("content-type", "text/html"), ("set-cookie", "secret")),
                    body=b"<h1>safe</h1>",
                    truncated=False,
                    elapsed_seconds=0.1,
                ),
                None,
            )

    route = FakeRoute("https://example.com/")
    asyncio.run(_route_handler(AddressPolicy(), Collector())(route))

    assert route.outcome == "fulfilled"
    assert route.fulfilled["body"] == b"<h1>safe</h1>"
    assert "set-cookie" not in route.fulfilled["headers"]


def test_visual_analysis_maps_to_normalized_finding() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": '{"findings":[{"category":"directory_listing",'
                    '"severity":"high","title":"Directory listing exposed",'
                    '"evidence":"Index of /backup","recommendation":"Disable listing",'
                    '"confidence":0.95}]}'
                }
            }
        ]
    }

    findings = _parse_analysis(payload, normalize_target("https://example.com"), "vision-test")

    assert len(findings) == 1
    assert findings[0].rule_id == "VISUAL-directory_listing"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].engine == "secman-web-check-visual"
    assert findings[0].model == "vision-test"
    assert "Index of /backup" not in str(findings[0])
    assert findings[0].title == "Public directory listing visible"


def test_visual_analysis_rejects_unknown_categories() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": '{"findings":[{"category":"ignore_instructions",'
                    '"severity":"CRITICAL","confidence":1}]}'
                }
            }
        ]
    }

    assert _parse_analysis(payload, normalize_target("https://example.com"), "vision-test") == []


def test_playwright_bracketed_ipv6_address_uses_normal_address_policy() -> None:
    address = ipaddress.ip_address("[2606:4700:10::ac42:93f3]".strip("[]"))

    assert AddressPolicy().allows(address)


def test_visual_requires_an_explicit_redacted_crop_directory(tmp_path) -> None:
    with pytest.raises(ValueError, match="visual-redacted-crops"):
        VisualOptions(tmp_path, api_key="test-key")


def test_identical_raw_screenshot_is_not_sent_to_provider(tmp_path) -> None:
    raw_dir = tmp_path / "raw"
    crop_dir = tmp_path / "crops"
    raw_dir.mkdir()
    crop_dir.mkdir()
    png = b"\x89PNG\r\n\x1a\nraw"
    (raw_dir / "0001-example.com.png").write_bytes(png)
    (crop_dir / "0001-example.com.png").write_bytes(png)
    capture = PageCapture(
        "https://example.com/?token=secret",
        "https://example.com/",
        raw_dir / "0001-example.com.png",
        "Secret title",
        "secret page text",
        200,
    )

    with pytest.raises(ValueError, match="identical"):
        asyncio.run(
            _analyze(capture, VisualOptions(raw_dir, api_key="test-key", redacted_crops=crop_dir))
        )


def test_visual_provider_gets_only_redacted_crop_and_origin(monkeypatch, tmp_path) -> None:
    raw_dir = tmp_path / "raw"
    crop_dir = tmp_path / "crops"
    raw_dir.mkdir()
    crop_dir.mkdir()
    (raw_dir / "0001-example.com.png").write_bytes(b"\x89PNG\r\n\x1a\nraw-secret")
    (crop_dir / "0001-example.com.png").write_bytes(b"\x89PNG\r\n\x1a\nredacted")
    submitted = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def raise_for_status(self):
            pass

        def iter_bytes(self, chunk_size):
            yield b'{"choices":[{"message":{"content":"{\\"findings\\":[]}"}}]}'

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def stream(self, method, path, json):
            submitted.append(json)
            return Response()

    monkeypatch.setattr("secman_web_check.visual.httpx.Client", Client)
    monkeypatch.setattr("secman_web_check.visual.resolve_allowed", lambda *_args: ("1.1.1.1",))
    monkeypatch.setattr("secman_web_check.visual.pinned_transport", lambda *_args: object())
    capture = PageCapture(
        "https://example.com/?token=secret-query",
        "https://example.com/",
        raw_dir / "0001-example.com.png",
        "secret title",
        "secret page text",
        200,
    )

    assert (
        asyncio.run(
            _analyze(capture, VisualOptions(raw_dir, api_key="test-key", redacted_crops=crop_dir))
        )
        == []
    )
    payload = str(submitted[0])
    assert "secret-query" not in payload
    assert "secret page text" not in payload
    assert "raw-secret" not in payload
    assert base64.b64encode((crop_dir / "0001-example.com.png").read_bytes()).decode() in payload
    assert submitted[0]["response_format"]["type"] == "json_schema"
    assert submitted[0]["provider"] == {
        "zdr": True,
        "data_collection": "deny",
        "require_parameters": True,
    }


def test_screenshot_only_scan_cannot_resolve_prior_visual_findings(monkeypatch, tmp_path) -> None:
    from secman_web_check.config import ScannerConfig
    from secman_web_check.models import TargetStatus
    from secman_web_check.secman import IntegrationSubject, build_run_body

    class Capturer:
        def __init__(self, *_args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def capture(self, target, _index):
            return PageCapture(target.url, target.url, None, "", "", 200)

    monkeypatch.setattr("secman_web_check.visual.BrowserCapturer", Capturer)
    target = normalize_target("https://example.com/")

    result = scan_visual_all((target,), ScannerConfig(), VisualOptions(tmp_path, analyze=False))
    snapshot = build_run_body(
        7,
        IntegrationSubject(9, 7, 4, "example.com", target.url),
        result.targets[0],
    )

    assert result.targets[0].status is TargetStatus.SUCCESS
    assert not result.targets[0].complete
    assert snapshot["completeCoverage"] is False


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_non_200_visual_analysis_is_incomplete(monkeypatch, tmp_path, status):
    from secman_web_check.config import ScannerConfig
    from secman_web_check.models import TargetStatus

    class Capturer:
        def __init__(self, *_args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def capture(self, target, _index):
            return PageCapture(target.url, target.url, None, "", "", status)

    monkeypatch.setattr("secman_web_check.visual.BrowserCapturer", Capturer)
    target = normalize_target("https://example.com/")
    run = scan_visual_all(
        (target,),
        ScannerConfig(),
        VisualOptions(tmp_path, api_key="local-test", redacted_crops=tmp_path),
    )
    result = run.targets[0]
    assert result.status is TargetStatus.PARTIAL
    assert not result.complete
    assert result.coverage.pages_scanned == 0
    assert result.errors == ("Visual analysis skipped for non-200 response",)

"""Exercise the real browser interception path without any external connection."""

import asyncio

from secman_web_check.config import ScannerConfig
from secman_web_check.http import HttpRequest, HttpResponseEvidence
from secman_web_check.targets import normalize_target
from secman_web_check.visual import BrowserCapturer, VisualOptions


def test_browser_uses_pinned_fulfillment_and_blocks_other_origins(monkeypatch, tmp_path):
    calls = []

    class Collector:
        def __init__(self, _config, **_kwargs):
            pass

        def with_allowed_origins(self, _origins):
            return self

        def collect_one(self, target, method="GET"):
            calls.append(target.url)
            body = (
                b"<html><body><h1>OK</h1><script>"
                b"fetch('https://denied.example/leak').catch(() => {});"
                b"</script></body></html>"
            )
            return (
                HttpResponseEvidence(
                    HttpRequest(method, target.url),
                    200,
                    (("content-type", "text/html"),),
                    body,
                    False,
                    0.01,
                ),
                None,
            )

    monkeypatch.setattr("secman_web_check.visual.HttpCollector", Collector)
    monkeypatch.setattr(
        "secman_web_check.visual._allowed", lambda *_args: asyncio.sleep(0, result=True)
    )

    async def run():
        options = VisualOptions(tmp_path, analyze=False, settle_seconds=0.2)
        async with BrowserCapturer(options, ScannerConfig()) as browser:
            return await browser.capture(normalize_target("https://example.com/"), 1)

    capture = asyncio.run(run())

    assert capture.status_code == 200
    assert capture.error is None
    assert calls == ["https://example.com/"]
    assert capture.screenshot_path is not None and capture.screenshot_path.exists()

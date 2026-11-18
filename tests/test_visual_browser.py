"""Exercise the real browser interception path without any external connection."""

import asyncio

import pytest

from secman_web_check.config import ScannerConfig
from secman_web_check.http import BrowserRedirectDenied, HttpRequest, HttpResponseEvidence
from secman_web_check.models import BrowserNavigationDiagnostic
from secman_web_check.targets import normalize_target
from secman_web_check.visual import BrowserCapturer, VisualOptions


@pytest.mark.parametrize(
    ("script", "extra_path", "navigation", "diagnostic"),
    [
        (b"", None, False, None),
        (b"<script>setTimeout(() => location.replace('/next'), 20)</script>", "/next", True, None),
        (
            b"<script type='module' src='/broken.js'></script>",
            "/broken.js",
            None,
            BrowserNavigationDiagnostic("script-failure"),
        ),
        (
            (
                b"<script>setTimeout(() => location.replace("
                b"'https://login.microsoftonline.com/authorize?state=fixture-secret'), 20)</script>"
            ),
            None,
            None,
            BrowserNavigationDiagnostic("blocked-origin", "login.microsoftonline.com"),
        ),
        (b"<iframe src='https://denied.example/frame'></iframe>", None, False, None),
        (
            b"",
            None,
            None,
            BrowserNavigationDiagnostic("blocked-http-redirect", "login.example"),
        ),
    ],
)
def test_browser_uses_pinned_fulfillment_and_blocks_other_origins(
    monkeypatch, tmp_path, script, extra_path, navigation, diagnostic
):
    calls = []

    class Collector:
        def __init__(self, _config, **_kwargs):
            pass

        def with_allowed_origins(self, _origins):
            return self

        def collect_one(self, target, method="GET", *, user_agent):
            calls.append(target.url)
            assert "Chrome/" in user_agent and "HeadlessChrome/" not in user_agent
            if diagnostic and diagnostic.reason == "blocked-http-redirect":
                raise BrowserRedirectDenied("login.example")
            body = (
                b"<html><body><h1>OK</h1><script>"
                b"fetch('https://denied.example/leak').catch(() => {});"
                b"</script>" + (script if target.url.endswith("/") else b"") + b"</body></html>"
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

    assert calls == ["https://example.com/"] + (
        [f"https://example.com{extra_path}"] if extra_path else []
    )
    assert capture.browser_navigation_observed is navigation
    assert capture.browser_navigation_diagnostic == diagnostic
    if diagnostic is None or diagnostic.hostname is None:
        assert capture.status_code == 200
        assert capture.error is None
        assert capture.screenshot_path is not None and capture.screenshot_path.exists()


@pytest.mark.parametrize(
    ("body", "server_redirect", "expected"),
    [
        (b"<script>location.replace('/next')</script>", False, True),
        (b"<script>setTimeout(() => location.replace('/next'), 100)</script>", False, True),
        (b'<meta http-equiv="refresh" content="0;url=/next">', False, True),
        (b"<p>no navigation</p>", False, False),
        (b"", True, True),
        (b"", "cross-origin", None),
    ],
)
def test_redirect_only_observes_main_frame_and_pins_server_hops(
    monkeypatch, tmp_path, body, server_redirect, expected
):
    calls = []

    class Collector:
        def __init__(self, *_args, **_kwargs):
            pass

        def with_allowed_origins(self, _origins):
            return self

        def collect_one(self, target, method="GET", *, user_agent):
            calls.append(target.url)
            initial = target.url == "https://example.com/"
            if target.host == "auth.example":
                raise BrowserRedirectDenied("login.example")
            redirect = None
            if initial and server_redirect:
                host = "auth.example" if server_redirect == "cross-origin" else "example.com"
                redirect = f"https://{host}/next"
            return HttpResponseEvidence(
                HttpRequest(method, target.url),
                302 if redirect else 200,
                (("content-type", "text/html"),),
                body if initial else b"done",
                False,
                0.01,
            ), redirect

    monkeypatch.setattr("secman_web_check.visual.HttpCollector", Collector)

    async def run():
        options = VisualOptions(
            tmp_path,
            analyze=False,
            capture_screenshots=False,
            redirect_only=True,
            settle_seconds=0.3,
            allowed_origins=frozenset({"https://auth.example"}),
        )
        async with BrowserCapturer(options, ScannerConfig()) as browser:
            return await browser.capture(normalize_target("https://example.com/"), 1)

    capture = asyncio.run(run())
    assert capture.browser_navigation_observed is expected, (capture.error, calls)
    if server_redirect == "cross-origin":
        assert calls == ["https://example.com/", "https://auth.example/next"]
        assert capture.browser_navigation_hops == ("auth.example", "login.example")
        assert capture.browser_navigation_diagnostic == BrowserNavigationDiagnostic(
            "blocked-http-redirect", "login.example"
        )
        return
    assert calls == ["https://example.com/"] + (["https://example.com/next"] if expected else [])
    assert capture.browser_navigation_hops == (("example.com",) if expected else ())

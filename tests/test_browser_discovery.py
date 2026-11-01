import asyncio

from secman_web_check.browser_discovery import BrowserDiscoveryOptions, discover_browser
from secman_web_check.config import ScannerConfig
from secman_web_check.http import HttpRequest, HttpResponseEvidence
from secman_web_check.targets import normalize_target


def test_real_browser_discovers_rendered_link_and_observes_api_but_blocks_writes(monkeypatch):
    calls = []

    class Collector:
        def __init__(self, *_args, **_kwargs):
            pass

        def with_allowed_origins(self, _origins):
            return self

        def collect_one(self, target, method="GET"):
            calls.append((method, target.url))
            body = b"<html><body>Rendered page</body></html>"
            mime = "text/html"
            if target.url == "https://example.com/":
                body = b"""<html><body><script>
                const link = document.createElement('a');
                link.href = '/rendered'; link.textContent = 'Rendered'; document.body.append(link);
                fetch('/api/items?token=SYNTHETIC').catch(() => {});
                fetch('/api/write', {method:'POST', body:'never transmitted'}).catch(() => {});
                fetch('https://outside.example/leak').catch(() => {});
                </script></body></html>"""
            elif "/api/items" in target.url:
                body, mime = b'{"synthetic":"transient only"}', "application/json"
            return HttpResponseEvidence(
                HttpRequest(method, target.url), 200, (("content-type", mime),), body, False, 0.0
            ), None

    monkeypatch.setattr("secman_web_check.visual.HttpCollector", Collector)
    monkeypatch.setattr(
        "secman_web_check.visual._allowed", lambda *_args: asyncio.sleep(0, result=True)
    )
    result = discover_browser(
        normalize_target("https://example.com/"),
        ScannerConfig(),
        BrowserDiscoveryOptions(max_pages=2),
    )
    assert ("GET", "https://example.com/rendered") in calls
    assert any("/api/items" in url for _, url in calls)
    assert all(
        method == "GET" and "outside.example" not in url and "/api/write" not in url
        for method, url in calls
    )
    read = next(item for item in result.operations if "/api/items" in item.path)
    assert read.executed and read.parameters == ("query:token:unknown",)
    assert "SYNTHETIC" not in repr(result.operations)
    write = next(item for item in result.operations if "/api/write" in item.path)
    assert write.method == "POST" and not write.executed
    assert not result.errors

from hashlib import sha256

from secman_web_check.http import CollectionError, HttpRequest, HttpResponseEvidence
from secman_web_check.javascript import inventory_javascript, referenced_javascript


def evidence(url, body, *, content_type="application/javascript", truncated=False):
    return HttpResponseEvidence(
        request=HttpRequest("GET", url),
        status_code=200,
        headers=(("content-type", content_type),),
        body=body,
        truncated=truncated,
        elapsed_seconds=0.1,
    )


def test_referenced_javascript_normalizes_deduplicates_and_rejects_embedded_schemes():
    page = evidence(
        "https://example.com/path/",
        b"""<script src="../app.js"></script><script src="../app.js"></script>
        <script src="https://cdn.example/lib.js?v=1"></script>
        <script src="data:text/javascript,alert(1)"></script>""",
        content_type="text/html; charset=utf-8",
    )

    assert referenced_javascript(page) == (
        "https://example.com/app.js",
        "https://cdn.example/lib.js?v=1",
    )


def test_inventory_hashes_bytes_without_retaining_them_and_reports_safe_errors():
    page = evidence(
        "https://example.com/",
        b'<script src="/ok.js"></script><script src="/bad.js"></script>',
        content_type="text/html",
    )

    class Collector:
        def collect(self, target):
            if target.url.endswith("bad.js"):
                raise CollectionError("upstream secret")
            return (evidence(target.url, b"console.log('ok')"),)

    inventory = inventory_javascript(page, Collector())

    assert inventory.assets[0].url == "https://example.com/ok.js"
    assert inventory.assets[0].sha256 == sha256(b"console.log('ok')").hexdigest()
    assert not hasattr(inventory.assets[0], "body")
    assert inventory.errors == ("JavaScript collection failed or referenced address was denied",)


def test_non_html_response_has_no_references():
    assert referenced_javascript(evidence("https://example.com/data", b"{}")) == ()

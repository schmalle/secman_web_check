from secman_web_check.crawler import CrawlOptions, allowed_origin, crawl, openapi_get_paths
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def response(url, body):
    return HttpResponseEvidence(
        HttpRequest("GET", url),
        200,
        (("content-type", "text/html"),),
        body,
        False,
        0.01,
    )


class Collector:
    def __init__(self, pages):
        self.pages = pages
        self.requested = []
        self.origins = None

    def with_allowed_origins(self, origins):
        self.origins = origins
        return self

    def with_max_redirects(self, _limit):
        return self

    def collect(self, target):
        self.requested.append(target.url)
        return (self.pages.get(target.url, response(target.url, b"")),)


def test_crawl_stays_in_origin_and_deduplicates_links():
    root = response(
        "https://example.com/",
        b'<a href="/one">1</a><a href="/one">again</a><a href="https://other.example/">outside</a>',
    )
    collector = Collector({"https://example.com/one": response("https://example.com/one", b"")})

    result = crawl(
        root,
        collector,
        CrawlOptions(frozenset({"https://example.com"}), requests_per_second=1_000),
    )

    assert collector.requested == [
        "https://example.com/one",
        "https://example.com/robots.txt",
        "https://example.com/sitemap.xml",
    ]
    assert result.complete
    assert result.requests == 3
    assert len(result.pages) == 2


def test_crawl_budget_marks_coverage_partial():
    root = response("https://example.com/", b'<a href="/one">1</a><a href="/two">2</a>')
    collector = Collector({"https://example.com/one": response("https://example.com/one", b"")})

    result = crawl(
        root,
        collector,
        CrawlOptions(frozenset({"https://example.com"}), max_pages=2, requests_per_second=1_000),
    )

    assert not result.complete
    assert result.errors == ("Crawl budget reached",)
    assert collector.requested == ["https://example.com/one"]


def test_allowed_origin_rejects_paths_and_queries():
    import pytest

    with pytest.raises(ValueError):
        allowed_origin("https://example.com/private")
    with pytest.raises(ValueError):
        allowed_origin("https://example.com/?token=value")


def test_openapi_seeds_only_literal_get_paths(tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{"paths":{"/health":{"get":{}},"/write":{"post":{}},'
        '"/users/{id}":{"get":{}},"//outside.example/":{"get":{}},'
        '"/../admin":{"get":{}}}}'
    )

    assert openapi_get_paths(spec) == ("/health",)


def test_sitemap_urls_enter_the_bounded_crawl_queue():
    root = response("https://example.com/", b"<html></html>")
    collector = Collector(
        {
            "https://example.com/sitemap.xml": response(
                "https://example.com/sitemap.xml",
                b"<urlset><url><loc>https://example.com/from-map</loc></url></urlset>",
            ),
            "https://example.com/from-map": response("https://example.com/from-map", b""),
        }
    )

    result = crawl(
        root,
        collector,
        CrawlOptions(frozenset({"https://example.com"}), requests_per_second=1_000),
    )

    assert result.complete
    assert "https://example.com/from-map" in collector.requested
    assert len(result.pages) == 2

"""Origin-scoped, bounded discovery of public HTML pages."""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from time import monotonic, sleep
from urllib.parse import urljoin, urlsplit, urlunsplit

from .http import CollectionError, HttpCollector, HttpResponseEvidence
from .targets import AddressDenied, TargetError, normalize_target


def origin(url: str) -> str:
    target = normalize_target(url)
    authority = f"[{target.host}]" if ":" in target.host else target.host
    if target.port is not None:
        authority += f":{target.port}"
    return f"{target.scheme}://{authority}"


def allowed_origin(value: str) -> str:
    target = normalize_target(value)
    parts = urlsplit(target.url)
    if parts.path != "/" or parts.query:
        raise TargetError("allowed origin must not include a path or query")
    return origin(target.url)


def canonical_page(value: str) -> str:
    target = normalize_target(value)
    parts = urlsplit(target.url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


class _Links(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and values.get("href"):
            self.base_url = urljoin(self.base_url, values["href"] or "")
        if tag == "a" and values.get("href"):
            self.urls.append(urljoin(self.base_url, values["href"] or ""))
        if tag == "form" and (values.get("method") or "get").lower() == "get":
            self.urls.append(urljoin(self.base_url, values.get("action") or ""))


def _links(response: HttpResponseEvidence) -> tuple[str, ...]:
    content_type = next(
        (value for name, value in response.headers if name.lower() == "content-type"), ""
    )
    if response.status_code != 200 or response.truncated:
        return ()
    if response.url.endswith("/robots.txt"):
        return tuple(
            line.split(":", 1)[1].strip()
            for line in response.body.decode("utf-8", errors="replace").splitlines()
            if line.lower().startswith("sitemap:")
        )[:100]
    if "xml" in content_type.lower() or response.url.endswith(".xml"):
        text = response.body.decode("utf-8", errors="replace")
        return tuple(unescape(value.strip()) for value in re.findall(r"<loc>([^<]+)</loc>", text))[
            :200
        ]
    if "html" not in content_type.lower():
        return ()
    parser = _Links(response.url)
    parser.feed(response.body.decode("utf-8", errors="replace"))
    parser.close()
    return tuple(parser.urls)


@dataclass(frozen=True, slots=True)
class CrawlOptions:
    allowed_origins: frozenset[str] = frozenset()
    max_pages: int = 50
    max_depth: int = 2
    max_requests: int = 200
    requests_per_second: float = 1.0
    seed_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.max_pages < 1
            or self.max_depth < 0
            or self.max_requests < 1
            or self.requests_per_second <= 0
        ):
            raise ValueError("crawl limits and allowed origins must be positive")


@dataclass(frozen=True, slots=True)
class CrawlResult:
    pages: tuple[HttpResponseEvidence, ...]
    discovered: int
    requests: int
    complete: bool
    errors: tuple[str, ...]


def crawl(
    root: HttpResponseEvidence, collector: HttpCollector, options: CrawlOptions
) -> CrawlResult:
    """Follow public GET links with fixed scope, depth, page and request bounds."""
    if origin(root.url) not in options.allowed_origins:
        return CrawlResult((), 0, 0, False, ("Root redirected outside crawl scope",))
    collector = collector.with_allowed_origins(options.allowed_origins)
    pages = [root]
    seen = {canonical_page(root.url)}
    queue: deque[tuple[str, int, bool]] = deque((url, 1, False) for url in _links(root))
    queue.extend((urljoin(origin(root.url), path), 1, False) for path in options.seed_paths)
    queue.extend(
        (urljoin(origin(root.url), path), 0, True) for path in ("/robots.txt", "/sitemap.xml")
    )
    discovered = 0
    requests = 0
    errors: list[str] = []
    next_request = monotonic()
    while queue:
        raw_url, depth, metadata = queue.popleft()
        try:
            url = canonical_page(raw_url)
            if origin(url) not in options.allowed_origins or url in seen:
                continue
        except (TargetError, ValueError):
            continue
        seen.add(url)
        if not metadata:
            discovered += 1
        if depth > options.max_depth:
            continue
        if len(pages) >= options.max_pages or requests >= options.max_requests:
            if metadata and len(pages) >= options.max_pages:
                continue
            return CrawlResult(tuple(pages), discovered, requests, False, ("Crawl budget reached",))
        delay = next_request - monotonic()
        if delay > 0:
            sleep(delay)
        next_request = monotonic() + 1.0 / options.requests_per_second
        try:
            responses = collector.with_max_redirects(options.max_requests - requests - 1).collect(
                normalize_target(url)
            )
            requests += len(responses)
            response = responses[-1]
            if response.blocked_redirect_reason == "Redirect limit reached":
                return CrawlResult(
                    tuple(pages), discovered, requests, False, ("Crawl request budget reached",)
                )
            if origin(response.url) not in options.allowed_origins:
                errors.append("Page redirected outside crawl scope")
                continue
        except (AddressDenied, CollectionError):
            requests += 1
            if not metadata:
                errors.append("Crawl request failed or address denied")
            continue
        if not metadata:
            pages.append(response)
        if metadata or depth < options.max_depth:
            queue.extend((link, 1 if metadata else depth + 1, False) for link in _links(response))
    return CrawlResult(tuple(pages), discovered, requests, not errors, tuple(dict.fromkeys(errors)))


def openapi_get_paths(path: Path) -> tuple[str, ...]:
    """Extract only literal public GET paths from a bounded local OpenAPI JSON document."""
    if path.stat().st_size > 1_000_000:
        raise ValueError("OpenAPI document exceeds the 1 MB limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise TypeError("OpenAPI document must contain a paths object")
    paths: list[str] = []
    for raw_path, operation in document["paths"].items():
        if (
            isinstance(raw_path, str)
            and raw_path.startswith("/")
            and not raw_path.startswith("//")
            and ".." not in raw_path.split("/")
            and "{" not in raw_path
            and "?" not in raw_path
            and "#" not in raw_path
            and "\\" not in raw_path
            and isinstance(operation, dict)
            and "get" in operation
        ):
            paths.append(raw_path)
    return tuple(dict.fromkeys(paths[:200]))

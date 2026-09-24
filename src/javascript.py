"""Opt-in collection and hashing of JavaScript referenced by an HTML response."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .http import CollectionError, HttpCollector, HttpResponseEvidence
from .models import JavaScriptAsset
from .targets import AddressDenied, TargetError, normalize_target


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "script":
            return
        values = {name.casefold(): value for name, value in attrs}
        source = values.get("src")
        if source:
            self.sources.append(source)


@dataclass(frozen=True, slots=True)
class JavaScriptInventory:
    assets: tuple[JavaScriptAsset, ...]
    errors: tuple[str, ...]


def referenced_javascript(response: HttpResponseEvidence) -> tuple[str, ...]:
    """Return unique, normalized HTTP(S) script URLs in document order."""
    content_type = next(
        (value for name, value in response.headers if name.casefold() == "content-type"), ""
    )
    if "html" not in content_type.casefold():
        return ()
    parser = _ScriptParser()
    parser.feed(response.body.decode("utf-8", errors="replace"))
    urls: list[str] = []
    seen: set[str] = set()
    for source in parser.sources:
        if urlsplit(source).scheme.casefold() in {"data", "blob", "javascript"}:
            continue
        try:
            url = normalize_target(urljoin(response.url, source)).url
        except (TargetError, ValueError):
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return tuple(urls)


def inventory_javascript(
    response: HttpResponseEvidence, collector: HttpCollector
) -> JavaScriptInventory:
    """Fetch each external script through the pinned collector and retain only metadata."""
    assets: list[JavaScriptAsset] = []
    errors: list[str] = []
    for url in referenced_javascript(response):
        try:
            script = collector.collect(normalize_target(url))[-1]
            assets.append(
                JavaScriptAsset(
                    url=script.url,
                    sha256=sha256(script.body).hexdigest(),
                    size_bytes=len(script.body),
                    status_code=script.status_code,
                    truncated=script.truncated,
                )
            )
            if script.truncated:
                errors.append("JavaScript response exceeded the configured limit")
        except (AddressDenied, CollectionError, TargetError, ValueError):
            errors.append("JavaScript collection failed or referenced address was denied")
    return JavaScriptInventory(tuple(assets), tuple(dict.fromkeys(errors)))


__all__ = ["JavaScriptInventory", "inventory_javascript", "referenced_javascript"]

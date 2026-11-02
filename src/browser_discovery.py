"""Opt-in rendered-link discovery with pinned read requests and transient evidence."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from .config import ScannerConfig
from .crawler import canonical_page, origin
from .http import HttpResponseEvidence
from .models import ApiOperation
from .targets import NormalizedTarget, TargetError, normalize_target
from .traffic import TrafficController


@dataclass(frozen=True, slots=True)
class BrowserDiscoveryOptions:
    allowed_origins: frozenset[str] = frozenset()
    max_pages: int = 20
    max_depth: int = 2


@dataclass(frozen=True, slots=True)
class BrowserDiscoveryResult:
    pages: tuple[HttpResponseEvidence, ...]
    operations: tuple[ApiOperation, ...]
    errors: tuple[str, ...]
    requests: int


def discover_browser(
    target: NormalizedTarget,
    config: ScannerConfig,
    options: BrowserDiscoveryOptions,
    traffic: TrafficController | None = None,
) -> BrowserDiscoveryResult:
    """Called inside a security target worker, so the outer hard deadline also applies."""
    from .visual import BrowserCapturer, VisualOptions

    async def run() -> BrowserDiscoveryResult:
        origins = options.allowed_origins | {origin(target.url)}
        visual = VisualOptions(
            Path("scan-output"),
            analyze=False,
            capture_screenshots=False,
            allowed_origins=origins,
            traffic=traffic,
        )
        queue = deque([(target.url, 0)])
        seen: set[str] = set()
        pages: list[HttpResponseEvidence] = []
        operations: list[ApiOperation] = []
        errors = []
        requests = 0
        deadline = monotonic() + config.target_timeout_seconds
        async with BrowserCapturer(visual, config) as browser:
            while queue:
                raw, depth = queue.popleft()
                try:
                    url = canonical_page(raw)
                    if origin(url) not in origins or url in seen:
                        continue
                except (TargetError, ValueError):
                    continue
                if len(seen) >= options.max_pages or monotonic() >= deadline:
                    errors.append("Browser discovery budget exhausted")
                    break
                seen.add(url)
                capture = await asyncio.wait_for(
                    browser.capture(normalize_target(url), len(seen)),
                    max(0.001, deadline - monotonic()),
                )
                requests += capture.request_count
                operations.extend(capture.api_operations)
                if capture.error:
                    errors.append("Browser discovery page failed")
                    continue
                pages.extend(
                    response
                    for response in capture.responses
                    if response.status_code == 200 and not response.truncated
                )
                if depth < options.max_depth:
                    queue.extend((link, depth + 1) for link in capture.discovered_urls)
        return BrowserDiscoveryResult(
            tuple(pages), tuple(dict.fromkeys(operations)), tuple(dict.fromkeys(errors)), requests
        )

    return asyncio.run(run())

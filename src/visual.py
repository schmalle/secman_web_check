"""Browser capture and optional vision analysis for explicitly selected targets."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from .config import ScannerConfig
from .crawler import origin
from .http import CollectionError, HttpCollector, RequestBudget, pinned_transport
from .models import (
    CoverageSummary,
    Finding,
    ScanRun,
    Severity,
    TargetResult,
    TargetStatus,
    public_url,
)
from .orchestrator import ProgressCallback
from .targets import (
    AddressDenied,
    AddressPolicy,
    NormalizedTarget,
    normalize_target,
    resolve_allowed,
)

_SYSTEM_PROMPT = """Review an operator-redacted web screenshot. Report only content visible
in the crop. A public page, login form, or generic error is not a finding. Return category,
severity and confidence only. Do not quote page text, URLs, credentials or secrets."""
_BLOCKED_RESOURCE_TYPES = frozenset({"media", "websocket"})
_VISUAL_CATEGORIES = {
    "directory_listing": "Public directory listing visible",
    "admin_console": "Administrative console visible",
    "sensitive_document": "Potentially sensitive document visible",
    "debug_output": "Debug information visible",
}


@dataclass(frozen=True, slots=True)
class VisualOptions:
    output_dir: Path
    analyze: bool = True
    api_key: str | None = None
    model: str = "anthropic/claude-sonnet-4.5"
    base_url: str = "https://openrouter.ai/api/v1"
    timeout_seconds: float = 30.0
    settle_seconds: float = 1.5
    viewport_width: int = 1440
    viewport_height: int = 900
    allowed_origins: frozenset[str] = frozenset()
    redacted_crops: Path | None = None

    def __post_init__(self) -> None:
        if self.analyze and not self.api_key:
            raise ValueError("visual analysis requires SECMAN_VISION_API_KEY or --visual-no-ai")
        if self.analyze and self.redacted_crops is None:
            raise ValueError("visual analysis requires --visual-redacted-crops or --visual-no-ai")
        provider = normalize_target(self.base_url)
        if provider.scheme != "https" or urlsplit(self.base_url).query:
            raise ValueError("visual analysis base URL must use HTTPS")
        if self.timeout_seconds <= 0 or self.settle_seconds < 0:
            raise ValueError("visual timeouts must be valid positive durations")


@dataclass(frozen=True, slots=True)
class PageCapture:
    requested_url: str
    final_url: str
    screenshot_path: Path | None
    title: str
    text: str
    status_code: int | None
    error: str | None = None
    request_count: int = 0


def _safe_name(target: NormalizedTarget, index: int) -> str:
    host = re.sub(r"[^A-Za-z0-9._-]+", "-", target.host).strip("-") or "target"
    return f"{index:04d}-{host}.png"


def _safe_error(error: BaseException) -> str:
    name = type(error).__name__
    return f"{name}: browser operation failed"


async def _allowed(url: str, policy: AddressPolicy) -> bool:
    try:
        target = normalize_target(url)
        await asyncio.to_thread(resolve_allowed, target, policy)
        return True
    except (AddressDenied, OSError, ValueError):
        return False


def _route_handler(
    policy: AddressPolicy,
    collector: HttpCollector | None = None,
    allowed_origins: frozenset[str] | None = None,
) -> Callable[[Any], Awaitable[None]]:
    pinned = collector or HttpCollector(ScannerConfig(allow_private_targets=policy.allow_private))

    async def handle(route: Any) -> None:
        request = route.request
        if urlsplit(request.url).scheme in {"data", "blob"}:
            await route.continue_()
            return
        if request.resource_type in _BLOCKED_RESOURCE_TYPES:
            await route.abort()
            return
        if getattr(request, "method", "GET") not in {"GET", "HEAD"}:
            await route.abort()
            return
        try:
            target = normalize_target(request.url)
            if allowed_origins is not None and origin(target.url) not in allowed_origins:
                await route.abort()
                return
            evidence, redirect = await asyncio.to_thread(
                pinned.collect_one, target, getattr(request, "method", "GET")
            )
        except (CollectionError, AddressDenied, ValueError):
            await route.abort()
            return
        headers = {
            name: value
            for name, value in evidence.headers
            if name.lower()
            not in {
                "set-cookie",
                "content-length",
                "content-encoding",
                "transfer-encoding",
                "location",
            }
        }
        if redirect is not None:
            headers["location"] = redirect
        await route.fulfill(status=evidence.status_code, headers=headers, body=evidence.body)

    return handle


class BrowserCapturer:
    """One browser with an isolated, target-scoped context for each capture."""

    def __init__(self, options: VisualOptions, config: ScannerConfig) -> None:
        self.options = options
        self.config = config
        self.policy = AddressPolicy.from_config(config)
        self._playwright: Any = None
        self._browser: Any = None
        self._screenshot_lock = asyncio.Lock()

    async def __aenter__(self) -> Self:
        from playwright.async_api import async_playwright

        self.options.output_dir.mkdir(parents=True, exist_ok=True)
        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-proxy-server"],
            )
        except Exception:
            await self.__aexit__()
            raise
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:  # noqa: BLE001, S110 - best-effort browser teardown
                pass
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:  # noqa: BLE001, S110 - best-effort driver teardown
                pass

    async def capture(self, target: NormalizedTarget, index: int) -> PageCapture:
        if self._browser is None:
            raise RuntimeError("browser capturer is not open")
        context = None
        page = None
        budget = RequestBudget(200, 1.0)
        try:
            origins = self.options.allowed_origins | {origin(target.url)}
            context = await self._browser.new_context(
                viewport={
                    "width": self.options.viewport_width,
                    "height": self.options.viewport_height,
                },
                service_workers="block",
                accept_downloads=False,
            )
            await context.add_init_script(
                "Object.defineProperty(window, 'RTCPeerConnection', {value: undefined});"
                "Object.defineProperty(window, 'webkitRTCPeerConnection', {value: undefined});"
                "Object.defineProperty(window, 'WebTransport', {value: undefined});"
                "Object.defineProperty(window, 'WebSocket', {value: undefined});"
                "Object.defineProperty(window, 'Worker', {value: undefined});"
                "Object.defineProperty(window, 'SharedWorker', {value: undefined});"
            )
            await context.route(
                "**/*",
                _route_handler(
                    self.policy,
                    HttpCollector(self.config, budget=budget).with_allowed_origins(origins),
                    origins,
                ),
            )
            page = await context.new_page()
            response = await page.goto(
                target.url,
                wait_until="load",
                timeout=int(self.options.timeout_seconds * 1000),
            )
            if self.options.settle_seconds:
                await page.wait_for_timeout(int(self.options.settle_seconds * 1000))
            final_url = page.url
            if origin(final_url) not in origins or not await _allowed(final_url, self.policy):
                return PageCapture(target.url, final_url, None, "", "", None, "redirect denied")
            remote = await response.server_addr() if response is not None else None
            remote_ip = remote.get("ipAddress") if remote else None
            if remote_ip:
                try:
                    connected_address = ipaddress.ip_address(remote_ip.strip("[]"))
                except ValueError:
                    return PageCapture(target.url, final_url, None, "", "", None, "address denied")
                if not self.policy.allows(connected_address):
                    return PageCapture(target.url, final_url, None, "", "", None, "address denied")
            status_code = None if response is None else response.status
            if status_code != 200:
                return PageCapture(target.url, final_url, None, "", "", status_code)
            title = (await page.title())[:300]
            text = re.sub(r"\s+", " ", await page.locator("body").inner_text())[:4000]
            path = self.options.output_dir / _safe_name(target, index)
            page_height = await page.evaluate(
                "() => Math.max(document.documentElement.scrollHeight, document.body.scrollHeight)"
            )
            async with self._screenshot_lock:
                if isinstance(page_height, int) and page_height > 4000:
                    await page.screenshot(
                        path=str(path),
                        clip={
                            "x": 0,
                            "y": 0,
                            "width": self.options.viewport_width,
                            "height": 4000,
                        },
                    )
                else:
                    await page.screenshot(path=str(path), full_page=True)
            return PageCapture(
                target.url,
                final_url,
                path,
                title,
                text,
                status_code,
                request_count=budget.count,
            )
        except Exception as error:  # noqa: BLE001 - isolate one browser target
            return PageCapture(
                target.url,
                page.url if page is not None else target.url,
                None,
                "",
                "",
                None,
                _safe_error(error),
                request_count=budget.count,
            )
        finally:
            if context is not None:
                await context.close()


def _parse_analysis(
    payload: Mapping[str, Any], target: NormalizedTarget, model: str
) -> list[Finding]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("vision provider returned no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise TypeError("vision provider returned no text")
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", content, re.DOTALL)
    document = json.loads(fenced.group(1) if fenced else content)
    rows = document.get("findings", []) if isinstance(document, dict) else []
    if not isinstance(rows, list):
        raise TypeError("vision findings must be a list")
    findings: list[Finding] = []
    for row in rows[:20]:
        if not isinstance(row, dict):
            continue
        category = re.sub(r"[^a-z0-9_-]+", "-", str(row.get("category", "")).lower())
        if category not in _VISUAL_CATEGORIES:
            continue
        severity_name = str(row.get("severity", "MEDIUM")).upper()
        severity = Severity.__members__.get(severity_name, Severity.MEDIUM)
        try:
            confidence = max(0.0, min(1.0, float(row.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        findings.append(
            Finding.create(
                f"VISUAL-{category}",
                target.url,
                severity,
                _VISUAL_CATEGORIES[category],
                confidence=confidence,
                description="A model flagged content in an operator-redacted screenshot crop.",
                recommendation="Review the local screenshot and confirm whether access is intended.",
                evidence="Model category from operator-redacted crop; human validation required",
                engine="secman-web-check-visual",
                model=model,
            )
        )
    return findings


async def _analyze(capture: PageCapture, options: VisualOptions) -> list[Finding]:
    if capture.screenshot_path is None or options.api_key is None:
        return []
    if options.redacted_crops is None:
        raise ValueError("Redacted crop is unavailable")
    crop_path = options.redacted_crops / capture.screenshot_path.name
    crop = crop_path.read_bytes()
    if (
        len(crop) > 2_000_000
        or not crop.startswith(b"\x89PNG\r\n\x1a\n")
        or hashlib.sha256(crop).digest()
        == hashlib.sha256(capture.screenshot_path.read_bytes()).digest()
    ):
        raise ValueError("Redacted crop is missing, invalid, or identical to the raw screenshot")
    encoded = base64.b64encode(crop).decode("ascii")
    prompt = f"Origin: {origin(capture.requested_url)}\nHTTP status: {capture.status_code}"
    body = {
        "model": options.model,
        "temperature": 0,
        "max_tokens": 2000,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "visual_observations",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "maxItems": 20,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "category": {
                                        "type": "string",
                                        "enum": list(_VISUAL_CATEGORIES),
                                    },
                                    "severity": {
                                        "type": "string",
                                        "enum": [item.value for item in Severity],
                                    },
                                    "confidence": {"type": "number"},
                                },
                                "required": ["category", "severity", "confidence"],
                                "additionalProperties": False,
                            },
                        }
                    },
                    "required": ["findings"],
                    "additionalProperties": False,
                },
            },
        },
        "provider": {"zdr": True, "data_collection": "deny", "require_parameters": True},
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{encoded}"}},
                ],
            },
        ],
    }
    provider = normalize_target(options.base_url)
    addresses = await asyncio.to_thread(resolve_allowed, provider, AddressPolicy())

    def post() -> dict[str, Any]:
        with (
            httpx.Client(
                base_url=options.base_url.rstrip("/"),
                headers={"Authorization": f"Bearer {options.api_key}"},
                timeout=options.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=pinned_transport(provider, addresses),
            ) as client,
            client.stream("POST", "/chat/completions", json=body) as response,
        ):
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes(chunk_size=16_384):
                raw.extend(chunk)
                if len(raw) > 65_536:
                    raise ValueError("Vision provider response exceeded the size limit")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise TypeError("vision provider returned an invalid response")
            return payload

    payload = await asyncio.to_thread(post)
    return _parse_analysis(payload, normalize_target(capture.requested_url), options.model)


async def _scan_visual_async(
    targets: Sequence[NormalizedTarget],
    config: ScannerConfig,
    options: VisualOptions,
    progress: ProgressCallback | None = None,
) -> ScanRun:
    started = datetime.now(UTC)
    completed = 0
    results: list[TargetResult | None] = [None] * len(targets)
    semaphore = asyncio.Semaphore(config.concurrency)
    async with BrowserCapturer(options, config) as capturer:

        async def process(index: int, target: NormalizedTarget) -> None:
            nonlocal completed
            target_started = datetime.now(UTC)
            async with semaphore:
                capture = await capturer.capture(target, index + 1)
            errors: list[str] = []
            findings: list[Finding] = []
            if capture.error:
                errors.append(capture.error)
            elif capture.status_code == 200 and options.analyze:
                try:
                    findings = await _analyze(capture, options)
                except (httpx.HTTPError, OSError, TypeError, ValueError):
                    errors.append("visual analysis failed")
            if not capture.error and capture.status_code != 200 and options.analyze:
                errors.append("Visual analysis skipped for non-200 response")
            complete = not errors and options.analyze
            result = TargetResult(
                target=target,
                status=TargetStatus.SUCCESS if not errors else TargetStatus.PARTIAL,
                findings=tuple(findings),
                coverage=CoverageSummary(
                    pages_scanned=1 if capture.status_code == 200 else 0,
                    pages=(public_url(capture.final_url),) if capture.status_code == 200 else (),
                    http_requests=capture.request_count,
                ),
                errors=tuple(errors),
                complete=complete,
                started_at=target_started,
                completed_at=datetime.now(UTC),
            )
            results[index] = result
            completed += 1
            if progress is not None:
                progress(completed, len(targets), result)

        await asyncio.gather(*(process(index, target) for index, target in enumerate(targets)))
    return ScanRun(
        run_id=str(uuid4()),
        targets=tuple(result for result in results if result is not None),
        started_at=started,
        completed_at=datetime.now(UTC),
        profile="visual-ai" if options.analyze else "visual-capture",
    )


def scan_visual_all(
    targets: Sequence[NormalizedTarget],
    config: ScannerConfig,
    options: VisualOptions,
    *,
    progress: ProgressCallback | None = None,
) -> ScanRun:
    """Capture and optionally analyze all targets while preserving input order."""
    return asyncio.run(_scan_visual_async(targets, config, options, progress))


def merge_runs(security: ScanRun, visual: ScanRun) -> ScanRun:
    """Merge same-target results for local reports; uploads retain separate snapshots."""
    visual_by_url = {result.target.url: result for result in visual.targets}
    merged: list[TargetResult] = []
    for left in security.targets:
        right = visual_by_url[left.target.url]
        complete = left.complete and right.complete
        merged.append(
            TargetResult(
                target=left.target,
                status=(
                    TargetStatus.SUCCESS
                    if left.status == right.status == TargetStatus.SUCCESS
                    else TargetStatus.PARTIAL
                ),
                findings=tuple(
                    {item.external_id: item for item in (*left.findings, *right.findings)}.values()
                ),
                components=left.components,
                exposure=left.exposure,
                inventory_complete=left.inventory_complete,
                coverage=left.coverage,
                errors=tuple(dict.fromkeys((*left.errors, *right.errors))),
                complete=complete,
                started_at=min(left.started_at, right.started_at),
                completed_at=max(left.completed_at, right.completed_at),
            )
        )
    return ScanRun(
        run_id=str(uuid4()),
        targets=tuple(merged),
        started_at=min(security.started_at, visual.started_at),
        completed_at=max(security.completed_at, visual.completed_at),
        profile=f"combined:{security.profile}+{visual.profile}",
    )

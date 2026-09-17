"""Browser capture and optional vision analysis for explicitly selected targets."""

from __future__ import annotations

import asyncio
import base64
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
from .http import pinned_transport
from .models import Finding, ScanRun, Severity, TargetResult, TargetStatus
from .targets import (
    AddressDenied,
    AddressPolicy,
    NormalizedTarget,
    normalize_target,
    resolve_allowed,
)

_SYSTEM_PROMPT = """You are reviewing a screenshot from an authorized web assessment.
Report only sensitive content actually visible in the screenshot or supplied page text.
A normal public page, a login form that gates content, or a generic error is not a finding.
Never reproduce a complete credential or secret. Return one JSON object with a findings array.
Each finding must contain category, severity, title, evidence, recommendation, and confidence."""
_BLOCKED_RESOURCE_TYPES = frozenset({"media", "websocket"})


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

    def __post_init__(self) -> None:
        if self.analyze and not self.api_key:
            raise ValueError("visual analysis requires SECMAN_VISION_API_KEY or --visual-no-ai")
        if not self.base_url.startswith("https://"):
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


def _route_handler(policy: AddressPolicy) -> Callable[[Any], Awaitable[None]]:
    async def handle(route: Any) -> None:
        request = route.request
        if urlsplit(request.url).scheme in {"data", "blob"}:
            await route.continue_()
            return
        if request.resource_type in _BLOCKED_RESOURCE_TYPES:
            await route.abort()
            return
        if not await _allowed(request.url, policy):
            await route.abort()
            return
        await route.continue_()

    return handle


class BrowserCapturer:
    """One isolated browser context with network policy applied to every request."""

    def __init__(self, options: VisualOptions, config: ScannerConfig) -> None:
        self.options = options
        self.policy = AddressPolicy.from_config(config)
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
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
            self._context = await self._browser.new_context(
                viewport={
                    "width": self.options.viewport_width,
                    "height": self.options.viewport_height,
                }
            )
            await self._context.route("**/*", _route_handler(self.policy))
        except Exception:
            await self.__aexit__()
            raise
        return self

    async def __aexit__(self, *_: object) -> None:
        for resource in (self._context, self._browser):
            if resource is not None:
                try:
                    await resource.close()
                except Exception:  # noqa: BLE001, S110 - best-effort browser teardown
                    pass
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:  # noqa: BLE001, S110 - best-effort driver teardown
                pass

    async def capture(self, target: NormalizedTarget, index: int) -> PageCapture:
        if self._context is None:
            raise RuntimeError("browser capturer is not open")
        page = await self._context.new_page()
        try:
            response = await page.goto(
                target.url,
                wait_until="load",
                timeout=int(self.options.timeout_seconds * 1000),
            )
            if self.options.settle_seconds:
                await page.wait_for_timeout(int(self.options.settle_seconds * 1000))
            final_url = page.url
            if not await _allowed(final_url, self.policy):
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
                None if response is None else response.status,
            )
        except Exception as error:  # noqa: BLE001 - isolate one browser target
            return PageCapture(target.url, page.url, None, "", "", None, _safe_error(error))
        finally:
            await page.close()


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
    for row in rows[:100]:
        if not isinstance(row, dict) or not str(row.get("title", "")).strip():
            continue
        category = re.sub(r"[^a-z0-9_-]+", "-", str(row.get("category", "other")).lower())
        severity_name = str(row.get("severity", "MEDIUM")).upper()
        severity = Severity.__members__.get(severity_name, Severity.MEDIUM)
        try:
            confidence = max(0.0, min(1.0, float(row.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        findings.append(
            Finding.create(
                f"VISUAL-{category or 'other'}",
                target.url,
                severity,
                str(row["title"])[:300],
                confidence=confidence,
                description="Sensitive content detected by screenshot analysis.",
                recommendation=str(row.get("recommendation", ""))[:2000],
                evidence=str(row.get("evidence", ""))[:2000],
                engine="secman-web-check-visual",
                model=model,
            )
        )
    return findings


async def _analyze(capture: PageCapture, options: VisualOptions) -> list[Finding]:
    if capture.screenshot_path is None or options.api_key is None:
        return []
    encoded = base64.b64encode(capture.screenshot_path.read_bytes()).decode("ascii")
    prompt = (
        f"Requested URL: {capture.requested_url}\nFinal URL: {capture.final_url}\n"
        f"HTTP status: {capture.status_code}\nTitle: {capture.title}\nPage text: {capture.text}"
    )
    body = {
        "model": options.model,
        "temperature": 0,
        "max_tokens": 2000,
        "response_format": {"type": "json_object"},
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

    def post() -> httpx.Response:
        with httpx.Client(
            base_url=options.base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {options.api_key}"},
            timeout=options.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=pinned_transport(provider, addresses),
        ) as client:
            return client.post("/chat/completions", json=body)

    response = await asyncio.to_thread(post)
    try:
        response.raise_for_status()
        payload = response.json()
    finally:
        response.close()
    if not isinstance(payload, dict):
        raise TypeError("vision provider returned an invalid response")
    return _parse_analysis(payload, normalize_target(capture.requested_url), options.model)


async def _scan_visual_async(
    targets: Sequence[NormalizedTarget], config: ScannerConfig, options: VisualOptions
) -> ScanRun:
    started = datetime.now(UTC)
    results: list[TargetResult | None] = [None] * len(targets)
    semaphore = asyncio.Semaphore(config.concurrency)
    async with BrowserCapturer(options, config) as capturer:

        async def process(index: int, target: NormalizedTarget) -> None:
            target_started = datetime.now(UTC)
            async with semaphore:
                capture = await capturer.capture(target, index + 1)
            errors: list[str] = []
            findings: list[Finding] = []
            if capture.error:
                errors.append(capture.error)
            elif options.analyze:
                try:
                    findings = await _analyze(capture, options)
                except (httpx.HTTPError, OSError, TypeError, ValueError):
                    errors.append("visual analysis failed")
            complete = not errors
            results[index] = TargetResult(
                target=target,
                status=TargetStatus.SUCCESS if complete else TargetStatus.PARTIAL,
                findings=tuple(findings),
                errors=tuple(errors),
                complete=complete,
                started_at=target_started,
                completed_at=datetime.now(UTC),
            )

        await asyncio.gather(*(process(index, target) for index, target in enumerate(targets)))
    return ScanRun(
        run_id=str(uuid4()),
        targets=tuple(result for result in results if result is not None),
        started_at=started,
        completed_at=datetime.now(UTC),
    )


def scan_visual_all(
    targets: Sequence[NormalizedTarget], config: ScannerConfig, options: VisualOptions
) -> ScanRun:
    """Capture and optionally analyze all targets while preserving input order."""
    return asyncio.run(_scan_visual_async(targets, config, options))


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
                status=TargetStatus.SUCCESS if complete else TargetStatus.PARTIAL,
                findings=tuple(
                    {item.external_id: item for item in (*left.findings, *right.findings)}.values()
                ),
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
    )

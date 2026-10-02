"""Bounded scan orchestration with deterministic batch result ordering."""

from __future__ import annotations

import multiprocessing
import os
import signal
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import UTC, datetime
from time import monotonic
from typing import Any
from uuid import uuid4

from .agent import AgentOptions, run_agent
from .checks import PASSIVE_CHECKS, CheckContext
from .checks.active import run_active_checks
from .checks.redirects import check_redirects
from .components import (
    detect_components,
    find_component_vulnerabilities,
    inventory_response_is_complete,
    sanitize_inventory_url,
)
from .config import ScannerConfig
from .crawler import CrawlOptions, crawl, origin
from .discovery import discover_paths
from .external_scanners import scan_with_external
from .http import CollectionError, HttpCollector, RequestBudget
from .models import (
    CoverageSummary,
    ExposureObservation,
    Reachability,
    ScanRun,
    TargetResult,
    TargetStatus,
    public_url,
)
from .targets import AddressDenied, AddressPolicy, NormalizedTarget, normalize_target
from .tls import TlsScanner

ProgressCallback = Callable[[int, int, TargetResult], None]
"""Receives (completed count, total count, result) once per finished target."""

_AUTHENTICATED_MARKER_BODY = b'{"message":"Missing Authentication Token"}'
"""Exact AWS API Gateway body (ignoring surrounding whitespace) of an authenticated endpoint."""


def _security_txt_target(target: NormalizedTarget) -> NormalizedTarget:
    authority = target.host if ":" not in target.host else f"[{target.host}]"
    if target.port is not None:
        authority = f"{authority}:{target.port}"
    return normalize_target(f"{target.scheme}://{authority}/.well-known/security.txt")


def scan_target(
    target: NormalizedTarget,
    config: ScannerConfig,
    *,
    collector: HttpCollector | None = None,
    tls_scanner: TlsScanner | None = None,
    dirbuster: bool = False,
    external_scanners: tuple[str, ...] = (),
    crawl_options: CrawlOptions | None = None,
    agent_options: AgentOptions | None = None,
) -> TargetResult:
    """Scan one explicit target; errors are sanitized and retained on its result."""
    started = datetime.now(UTC)
    http = (
        collector
        if collector is not None
        else HttpCollector(
            config,
            budget=RequestBudget(
                crawl_options.max_requests if crawl_options is not None else 200,
                crawl_options.requests_per_second if crawl_options is not None else 1.0,
            ),
        )
    )
    deadline = monotonic() + config.target_timeout_seconds
    if isinstance(http, HttpCollector):
        http = http.with_deadline(deadline)
    if crawl_options is not None:
        crawl_options = replace(
            crawl_options,
            allowed_origins=crawl_options.allowed_origins | {origin(target.url)},
        )
        http = http.with_allowed_origins(crawl_options.allowed_origins)
    tls = tls_scanner if tls_scanner is not None else TlsScanner(config)
    errors: list[str] = []
    try:
        responses = http.collect(target)
        response = responses[-1]
        effective_target = normalize_target(response.url)
    except (AddressDenied, CollectionError):
        return TargetResult(
            target=target,
            status=TargetStatus.FAILED,
            exposure=ExposureObservation(
                configured_url=sanitize_inventory_url(target.url) or target.url,
                effective_url=None,
                reachability=Reachability.UNKNOWN,
                http_status=None,
                redirect_count=0,
            ),
            errors=("HTTP collection failed or target address was denied",),
            complete=False,
            started_at=started,
            completed_at=datetime.now(UTC),
        )

    if response.truncated:
        errors.append("HTTP response body exceeded the configured limit")
    security_txt = None
    try:
        security_txt = http.with_max_body_bytes(min(config.max_body_bytes, 65_536)).collect(
            _security_txt_target(effective_target)
        )[-1]
        if security_txt.truncated:
            errors.append("security.txt exceeded the configured limit")
    except (AddressDenied, CollectionError):
        errors.append("security.txt collection failed")

    context = CheckContext(response=response, security_txt=security_txt)
    findings = list(check_redirects(responses))
    findings.extend(finding for check in PASSIVE_CHECKS for finding in check(context))
    optional_scope_allowed = origin(target.url) == origin(effective_target.url)
    if not optional_scope_allowed and (
        config.active or dirbuster or external_scanners or agent_options is not None
    ):
        errors.append("Optional probes skipped after cross-origin redirect")
    active_http = (
        http.with_allowed_origins(frozenset({origin(effective_target.url)}))
        if config.active and optional_scope_allowed
        else http
    )
    active_result = run_active_checks(
        context,
        active_http,
        enabled=config.active and agent_options is None and optional_scope_allowed,
    )
    findings.extend(active_result.findings)
    errors.extend(active_result.errors)

    # Additional requests are strictly opt-in and only run after a successful root response.
    if response.status_code == 200 and dirbuster and optional_scope_allowed:
        discovery = discover_paths(effective_target, http)
        findings.extend(discovery.findings)
        errors.extend(discovery.errors)
    if response.status_code == 200 and external_scanners and optional_scope_allowed:
        external = scan_with_external(
            effective_target,
            external_scanners,
            policy=AddressPolicy.from_config(config),
        )
        findings.extend(external.findings)
        errors.extend(external.errors)

    try:
        tls_evidence, tls_findings = tls.scan(effective_target)
        findings.extend(tls_findings)
        errors.extend(tls_evidence.errors)
    except (AddressDenied, OSError, RuntimeError, StopIteration, ValueError):
        errors.append("TLS analysis failed")

    components = list(detect_components(response))
    findings.extend(find_component_vulnerabilities(tuple(components), target.url))
    coverage = CoverageSummary(pages_scanned=1, pages=(public_url(response.url),))
    if crawl_options is not None:
        discovered = crawl(response, http, crawl_options)
        errors.extend(discovered.errors)
        coverage = CoverageSummary(
            pages_scanned=len(discovered.pages),
            pages_discovered=discovered.discovered,
            pages=tuple(public_url(page.url) for page in discovered.pages),
            crawl_requests=discovered.requests,
            crawl_complete=discovered.complete,
        )
        for page in discovered.pages[1:]:
            page_context = CheckContext(response=page)
            findings.extend(finding for check in PASSIVE_CHECKS for finding in check(page_context))
            page_components = detect_components(page)
            components.extend(page_components)
            findings.extend(find_component_vulnerabilities(page_components, page.url))
    if agent_options is not None and optional_scope_allowed:
        agent_result = run_agent(
            context, active_http, agent_options, findings, active=config.active
        )
        findings.extend(agent_result.findings)
        errors.extend(agent_result.errors)
        coverage = replace(
            coverage,
            agent_actions=agent_result.actions,
            agent_complete=agent_result.complete,
        )
    elif agent_options is not None:
        coverage = replace(coverage, agent_complete=False)
    components = list({component.component_key: component for component in components}.values())
    coverage = replace(coverage, http_requests=getattr(http, "request_count", 0))
    unique = {finding.external_id: finding for finding in findings}
    if monotonic() >= deadline:
        errors.append("Target deadline exceeded")
    complete = not errors and coverage.crawl_complete and coverage.agent_complete
    reachability = (
        Reachability.AUTHENTICATED
        if response.body.strip() == _AUTHENTICATED_MARKER_BODY
        else Reachability.REACHABLE
    )
    return TargetResult(
        target=target,
        status=TargetStatus.SUCCESS if complete else TargetStatus.PARTIAL,
        findings=tuple(unique.values()),
        components=tuple(components),
        coverage=coverage,
        exposure=ExposureObservation(
            configured_url=sanitize_inventory_url(target.url) or target.url,
            effective_url=sanitize_inventory_url(response.url),
            reachability=reachability,
            http_status=response.status_code,
            redirect_count=max(0, len(responses) - 1),
            body_length=len(response.body),
        ),
        inventory_complete=inventory_response_is_complete(response) and coverage.crawl_complete,
        errors=tuple(dict.fromkeys(errors)),
        complete=complete,
        started_at=started,
        completed_at=datetime.now(UTC),
    )


def _target_worker(
    connection: Any, target: NormalizedTarget, config: ScannerConfig, options: dict[str, Any]
) -> None:
    # Own a process group so timeout cleanup also stops optional scanner subprocesses.
    if os.name == "posix":
        os.setsid()
    try:
        connection.send(scan_target(target, config, **options))
    except Exception:  # noqa: BLE001 - return only sanitized parent-owned failures
        connection.send(None)
    finally:
        connection.close()


def _bounded_scan_target(
    target: NormalizedTarget, config: ScannerConfig, **options: Any
) -> TargetResult:
    started = datetime.now(UTC)
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_target_worker, args=(writer, target, config, options))
    try:
        process.start()
        writer.close()
        if reader.poll(config.target_timeout_seconds):
            try:
                result = reader.recv()
                if isinstance(result, TargetResult):
                    return result
            except EOFError:
                pass
            error = "Unexpected target scan failure"
        else:
            error = "Target deadline exceeded"
        return TargetResult(
            target=target,
            status=TargetStatus.FAILED,
            errors=(error,),
            complete=False,
            started_at=started,
            completed_at=datetime.now(UTC),
        )
    finally:
        reader.close()
        writer.close()
        if process.pid is not None:
            # Kill our worker group even if its leader already exited with descendants.
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    if process.is_alive():
                        process.kill()
            elif process.is_alive():
                process.kill()
            process.join(timeout=5)
            process.close()


def scan_all(
    targets: tuple[NormalizedTarget, ...],
    config: ScannerConfig,
    *,
    progress: ProgressCallback | None = None,
    dirbuster: bool = False,
    external_scanners: tuple[str, ...] = (),
    crawl_options: CrawlOptions | None = None,
    agent_options: AgentOptions | None = None,
) -> ScanRun:
    """Scan a bounded target list concurrently without cancelling sibling targets."""
    started = datetime.now(UTC)
    completed = 0
    results: list[TargetResult | None] = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        future_indexes = {}
        for index, target in enumerate(targets):
            if (
                dirbuster
                or external_scanners
                or crawl_options is not None
                or agent_options is not None
            ):
                future = executor.submit(
                    _bounded_scan_target,
                    target,
                    config,
                    dirbuster=dirbuster,
                    external_scanners=external_scanners,
                    crawl_options=crawl_options,
                    agent_options=agent_options,
                )
            else:
                future = executor.submit(_bounded_scan_target, target, config)
            future_indexes[future] = index
        for future in as_completed(future_indexes):
            index = future_indexes[future]
            try:
                result = future.result()
            except Exception:  # noqa: BLE001 - isolate unexpected failure to one target
                now = datetime.now(UTC)
                result = TargetResult(
                    target=targets[index],
                    status=TargetStatus.FAILED,
                    errors=("Unexpected target scan failure",),
                    complete=False,
                    started_at=now,
                    completed_at=now,
                )
            results[index] = result
            completed += 1
            if progress is not None:
                progress(completed, len(targets), result)
    return ScanRun(
        run_id=str(uuid4()),
        targets=tuple(result for result in results if result is not None),
        started_at=started,
        completed_at=datetime.now(UTC),
        profile="security:"
        + (
            ",".join(
                name
                for enabled, name in (
                    (config.active, "active"),
                    (crawl_options is not None, "crawl"),
                    (dirbuster, "dirbuster"),
                    (bool(external_scanners), "external"),
                    (agent_options is not None, "ai-agent"),
                )
                if enabled
            )
            or "passive"
        ),
    )


__all__ = ["ProgressCallback", "scan_all", "scan_target"]

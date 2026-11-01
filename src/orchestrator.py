"""Bounded scan orchestration with deterministic batch result ordering."""

from __future__ import annotations

import multiprocessing
import os
import signal
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from time import monotonic
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from .agent import _SYSTEM, AgentOptions, run_agent
from .browser_discovery import BrowserDiscoveryOptions, discover_browser
from .checks import CheckContext, evaluate_passive
from .checks.active import ACTIVE_PROBES, run_active_checks
from .checks.redirects import check_redirects
from .components import (
    detect_components,
    find_component_vulnerabilities,
    inventory_response_is_complete,
    sanitize_inventory_url,
)
from .config import ScannerConfig
from .coverage import manifest, outcome
from .crawler import CrawlOptions, crawl, origin
from .discovery import discover_paths
from .external_profile import ExternalProfile
from .external_scanners import scan_with_external
from .http import CollectionError, HttpCollector, RequestBudget
from .intelligence import AdvisorySnapshot
from .javascript import inventory_javascript
from .models import (
    AnalysisStage,
    ApiOperation,
    CheckExecution,
    CoverageSummary,
    ExposureObservation,
    Finding,
    JavaScriptAsset,
    Reachability,
    ScanRun,
    TargetResult,
    TargetStatus,
    public_url,
)
from .provider import POLICY_VERSION
from .targets import AddressDenied, AddressPolicy, NormalizedTarget, normalize_target
from .tls import TlsScanner
from .traffic import TrafficController, traffic_run

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
    external_profile: ExternalProfile | None = None,
    crawl_options: CrawlOptions | None = None,
    agent_options: AgentOptions | None = None,
    javascript: bool = False,
    script_origins: frozenset[str] = frozenset(),
    traffic: TrafficController | None = None,
    browser_options: BrowserDiscoveryOptions | None = None,
    api_operations: tuple[ApiOperation, ...] = (),
    advisory_snapshot: AdvisorySnapshot | None = None,
) -> TargetResult:
    """Scan one explicit target; errors are sanitized and retained on its result."""
    started = datetime.now(UTC)
    traffic = traffic or TrafficController(config)
    if agent_options is not None:
        agent_options = replace(agent_options, traffic=traffic)
    http = (
        collector
        if collector is not None
        else HttpCollector(
            config,
            traffic=traffic,
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
    tls = tls_scanner if tls_scanner is not None else TlsScanner(config, traffic=traffic)
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
    checked, initial_executions = evaluate_passive(context)
    findings.extend(checked)
    executions = list(initial_executions)
    stages = []
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
    for probe in ACTIVE_PROBES:
        observed = tuple(item for item in active_result.findings if item.rule_id == probe.rule_id)
        if config.active and agent_options is None and optional_scope_allowed:
            state = (
                "failed"
                if active_result.errors
                else "executed-positive"
                if observed
                else "executed-negative"
            )
        else:
            state = "skipped"
        executions.append(
            CheckExecution(
                probe.rule_id,
                response.url,
                state,
                tuple(identifier for item in observed for identifier in item.evidence_ids),
                "" if state != "skipped" else "Opt-in disabled, agent selected, or scope denied",
            )
        )
    findings.extend(active_result.findings)
    errors.extend(active_result.errors)

    # Additional requests are strictly opt-in and only run after a successful root response.
    if response.status_code == 200 and dirbuster and optional_scope_allowed:
        discovery = discover_paths(effective_target, http)
        findings.extend(discovery.findings)
        errors.extend(discovery.errors)
        executions.append(
            CheckExecution(
                "dirbuster",
                target.url,
                "failed"
                if discovery.errors
                else "executed-positive"
                if discovery.findings
                else "executed-negative",
            )
        )
    else:
        executions.append(
            CheckExecution(
                "dirbuster",
                target.url,
                "skipped",
                reason="Opt-in disabled, non-200 response, or scope denied",
            )
        )
    if response.status_code == 200 and external_scanners and optional_scope_allowed:
        external = scan_with_external(
            effective_target,
            external_scanners,
            policy=AddressPolicy.from_config(config),
            profile=external_profile,
            traffic=traffic,
        )
        findings.extend(external.findings)
        errors.extend(external.errors)
        executions.append(
            CheckExecution(
                "external",
                target.url,
                "failed"
                if external.errors
                else "executed-positive"
                if external.findings
                else "executed-negative",
            )
        )
    else:
        executions.append(
            CheckExecution(
                "external",
                target.url,
                "skipped",
                reason="Opt-in disabled, non-200 response, or scope denied",
            )
        )

    javascript_assets: tuple[JavaScriptAsset, ...] = ()
    if javascript:
        inventory = inventory_javascript(response, http, allowed_origins=script_origins)
        javascript_assets = inventory.assets
        errors.extend(inventory.errors)
        executions.append(
            CheckExecution(
                "javascript",
                target.url,
                "unsupported"
                if not context.is_html
                else "failed"
                if inventory.errors
                else "executed-positive"
                if inventory.assets
                else "executed-negative",
            )
        )
    else:
        executions.append(
            CheckExecution("javascript", target.url, "skipped", reason="Explicit opt-in disabled")
        )

    tls_failed = False
    tls_findings: tuple[Finding, ...] = ()
    try:
        tls_evidence, tls_findings = tls.scan(effective_target)
        findings.extend(tls_findings)
        executions.append(
            outcome("tls:inventory", effective_target.url, tls_findings)
            if target.scheme == "https" and not tls_evidence.errors
            else CheckExecution(
                "tls:inventory", target.url, "failed" if tls_evidence.errors else "unsupported"
            )
        )
        tls_failed = bool(tls_evidence.errors)
        errors.extend(tls_evidence.errors)
    except (AddressDenied, OSError, RuntimeError, StopIteration, ValueError):
        errors.append("TLS analysis failed")
        tls_failed = True
        executions.append(CheckExecution("tls:inventory", target.url, "failed"))

    vulnerability_rules = {
        "WEB-TLS-HEARTBLEED",
        "WEB-TLS-ROBOT",
        "WEB-TLS-CCS-INJECTION",
        "WEB-TLS-FALLBACK-SCSV-MISSING",
        "WEB-TLS-INSECURE-RENEGOTIATION",
        "WEB-TLS-CLIENT-RENEGOTIATION-DOS",
    }
    for rule_id in sorted(vulnerability_rules):
        state = (
            "unsupported"
            if effective_target.scheme != "https"
            else "skipped"
            if not config.tls_vulnerabilities
            else "failed"
            if tls_failed
            else "executed-positive"
            if any(item.rule_id == rule_id for item in tls_findings)
            else "executed-negative"
        )
        executions.append(
            CheckExecution(
                rule_id,
                effective_target.url,
                state,
                tuple(
                    identifier
                    for item in tls_findings
                    if item.rule_id == rule_id
                    for identifier in item.evidence_ids
                ),
                "Separate TLS vulnerability opt-in" if state == "skipped" else "",
            )
        )
    components = list(detect_components(response))
    findings.extend(
        advisory_snapshot.findings(tuple(components), target.url)
        if advisory_snapshot
        else find_component_vulnerabilities(tuple(components), target.url)
    )
    executions.append(
        CheckExecution(
            "components:advisories",
            target.url,
            "failed"
            if advisory_snapshot and advisory_snapshot.stale
            else "executed-positive"
            if any(item.rule_id.startswith("WEB-COMPONENT-") for item in findings)
            else "executed-negative",
            reason="Maintained snapshot"
            if advisory_snapshot
            else "Bundled legacy advisory subset; freshness unverified",
        )
    )
    if advisory_snapshot and advisory_snapshot.provenance()["unsupportedRanges"]:
        errors.append("Advisory snapshot contains unsupported ranges or packages")
    if advisory_snapshot and advisory_snapshot.stale:
        errors.append("Advisory snapshot is older than 30 days")
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
            page_findings, page_executions = evaluate_passive(page_context)
            findings.extend(page_findings)
            executions.extend(page_executions)
            page_components = detect_components(page)
            components.extend(page_components)
            findings.extend(
                advisory_snapshot.findings(page_components, page.url)
                if advisory_snapshot
                else find_component_vulnerabilities(page_components, page.url)
            )
    if browser_options is not None and optional_scope_allowed:
        try:
            rendered = discover_browser(effective_target, config, browser_options, traffic)
            errors.extend(rendered.errors)
            api_operations = tuple(dict.fromkeys((*api_operations, *rendered.operations)))
            for page in rendered.pages:
                page_findings, page_executions = evaluate_passive(CheckContext(page))
                executions.extend(page_executions)
                findings.extend(page_findings)
                executions.append(outcome("browser:passive", page.url, page_findings))
                page_components = detect_components(page)
                components.extend(page_components)
                findings.extend(
                    advisory_snapshot.findings(page_components, page.url)
                    if advisory_snapshot
                    else find_component_vulnerabilities(page_components, page.url)
                )
            coverage = replace(
                coverage,
                pages_scanned=coverage.pages_scanned + len(rendered.pages),
                pages=tuple(
                    dict.fromkeys(
                        (*coverage.pages, *(public_url(page.url) for page in rendered.pages))
                    )
                ),
                http_requests=rendered.requests,
            )
            executions.append(
                CheckExecution(
                    "browser:discovery",
                    target.url,
                    "failed" if rendered.errors else "executed-negative",
                )
            )
        except (OSError, RuntimeError, TimeoutError, ValueError):
            errors.append("Browser discovery failed or exhausted its budget")
            executions.append(CheckExecution("browser:discovery", target.url, "exhausted"))
    else:
        executions.append(
            CheckExecution(
                "browser:discovery",
                target.url,
                "skipped",
                reason="Opt-in disabled or redirect outside scope",
            )
        )
    if agent_options is not None and optional_scope_allowed:
        agent_started = datetime.now(UTC)
        agent_result = run_agent(
            context, active_http, agent_options, findings, active=config.active
        )
        findings.extend(agent_result.findings)
        executed_ids = {item.check_id for item in agent_result.executions}
        executions = [item for item in executions if item.check_id not in executed_ids]
        executions.extend(agent_result.executions)
        stages.append(
            AnalysisStage(
                "ai-agent",
                "complete" if agent_result.complete else "partial",
                agent_started,
                datetime.now(UTC),
                agent_options.model,
                sha256(_SYSTEM.encode()).hexdigest(),
                POLICY_VERSION,
            )
        )
        errors.extend(agent_result.errors)
        coverage = replace(
            coverage,
            agent_actions=agent_result.actions,
            agent_complete=agent_result.complete,
        )
    elif agent_options is not None:
        coverage = replace(coverage, agent_complete=False)
    executions.append(
        CheckExecution(
            "crawl",
            target.url,
            "failed"
            if crawl_options and not coverage.crawl_complete
            else "executed-negative"
            if crawl_options
            else "skipped",
            reason="" if crawl_options else "Explicit opt-in disabled",
        )
    )
    visited_paths = {urlsplit(url).path for url in coverage.pages}
    api_operations = tuple(
        replace(item, executed=True)
        if item.source == "openapi" and item.method == "GET" and item.path in visited_paths
        else item
        for item in api_operations
    )
    components = list({component.component_key: component for component in components}.values())
    coverage = replace(
        coverage,
        http_requests=coverage.http_requests + getattr(http, "request_count", 0),
        executions=tuple(executions),
        query_input=bool(urlsplit(target.url).query),
    )
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
        javascript_assets=javascript_assets,
        api_operations=api_operations,
        analysis_stages=tuple(stages),
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
        operation = options.pop("_operation", "security")
        if operation == "visual":
            import asyncio

            from .visual import _scan_visual_async

            result = asyncio.run(
                _scan_visual_async((target,), config, options["visual_options"], None)
            ).targets[0]
        else:
            result = scan_target(target, config, **options)
        connection.send(result)
    except Exception:  # noqa: BLE001 - return only sanitized parent-owned failures
        connection.send(None)
    finally:
        connection.close()


def _bounded_scan_target(
    target: NormalizedTarget, config: ScannerConfig, **options: Any
) -> TargetResult:
    traffic = options.get("traffic")
    if traffic is not None and traffic.cancelled:
        return TargetResult(target, TargetStatus.FAILED, errors=("Run cancelled",), complete=False)
    started = datetime.now(UTC)
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_target_worker, args=(writer, target, config, options))
    try:
        process.start()
        writer.close()
        wait_deadline = monotonic() + config.target_timeout_seconds
        traffic = options.get("traffic")
        ready = False
        while monotonic() < wait_deadline:
            if traffic is not None and traffic.cancelled:
                break
            if reader.poll(min(0.1, max(0.0, wait_deadline - monotonic()))):
                ready = True
                break
        if ready:
            try:
                result = reader.recv()
                if isinstance(result, TargetResult):
                    return result
            except EOFError:
                pass
            error = "Unexpected target scan failure"
        else:
            error = (
                "Run cancelled"
                if traffic is not None and traffic.cancelled
                else "Target deadline exceeded"
            )
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
            traffic = options.get("traffic")
            if traffic is not None:
                traffic.release_owner(process.pid)
            process.join(timeout=5)
            process.close()


def scan_all(
    targets: tuple[NormalizedTarget, ...],
    config: ScannerConfig,
    *,
    progress: ProgressCallback | None = None,
    dirbuster: bool = False,
    external_scanners: tuple[str, ...] = (),
    external_profile: ExternalProfile | None = None,
    crawl_options: CrawlOptions | None = None,
    agent_options: AgentOptions | None = None,
    javascript: bool = False,
    script_origins: frozenset[str] = frozenset(),
    traffic: TrafficController | None = None,
    browser_options: BrowserDiscoveryOptions | None = None,
    api_operations: tuple[ApiOperation, ...] = (),
    advisory_snapshot: AdvisorySnapshot | None = None,
) -> ScanRun:
    """Scan a bounded target list concurrently without cancelling sibling targets."""
    if traffic is None:
        with traffic_run(config) as shared:
            return scan_all(
                targets,
                config,
                progress=progress,
                dirbuster=dirbuster,
                external_scanners=external_scanners,
                external_profile=external_profile,
                crawl_options=crawl_options,
                agent_options=agent_options,
                javascript=javascript,
                script_origins=script_origins,
                traffic=shared,
                browser_options=browser_options,
                api_operations=api_operations,
                advisory_snapshot=advisory_snapshot,
            )
    started = datetime.now(UTC)
    completed = 0
    results: list[TargetResult | None] = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        future_indexes = {}
        for index, target in enumerate(targets):
            if (
                browser_options is not None
                or bool(api_operations)
                or advisory_snapshot is not None
                or dirbuster
                or external_scanners
                or javascript
                or crawl_options is not None
                or agent_options is not None
            ):
                future = executor.submit(
                    _bounded_scan_target,
                    target,
                    config,
                    dirbuster=dirbuster,
                    external_scanners=external_scanners,
                    external_profile=external_profile,
                    crawl_options=crawl_options,
                    agent_options=agent_options,
                    javascript=javascript,
                    script_origins=script_origins,
                    traffic=traffic,
                    browser_options=browser_options,
                    api_operations=api_operations,
                    advisory_snapshot=advisory_snapshot,
                )
            else:
                future = executor.submit(_bounded_scan_target, target, config, traffic=traffic)
            future_indexes[future] = index
        try:
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
        except KeyboardInterrupt:
            traffic.cancel()
            for future, index in future_indexes.items():
                if results[index] is None:
                    future.cancel()
                    if future.done() and not future.cancelled():
                        try:
                            results[index] = future.result()
                        except Exception:  # noqa: BLE001 - preserve sibling results during cancellation
                            results[index] = TargetResult(
                                targets[index],
                                TargetStatus.FAILED,
                                errors=("Unexpected target scan failure",),
                                complete=False,
                            )
                    else:
                        results[index] = TargetResult(
                            targets[index],
                            TargetStatus.FAILED,
                            errors=("Run cancelled",),
                            complete=False,
                        )
    return ScanRun(
        run_id=str(uuid4()),
        targets=tuple(result for result in results if result is not None),
        started_at=started,
        completed_at=datetime.now(UTC),
        manifest_json=manifest(
            config,
            javascript=javascript,
            dirbuster=dirbuster,
            scriptOrigins=sorted(script_origins),
            browser=None
            if browser_options is None
            else {
                "maxPages": browser_options.max_pages,
                "maxDepth": browser_options.max_depth,
                "origins": sorted(browser_options.allowed_origins),
            },
            api=[
                {
                    "path": item.path,
                    "method": item.method,
                    "parameters": list(item.parameters),
                    "requestContentTypes": list(item.request_content_types),
                    "responseContentTypes": list(item.response_content_types),
                    "authenticated": item.authenticated,
                }
                for item in api_operations
            ],
            advisories=advisory_snapshot.provenance()
            if advisory_snapshot
            else {"source": "bundled-legacy", "freshness": "unverified"},
            external=list(external_scanners),
            externalProfile=external_profile.provenance() if external_profile else None,
            crawl=None
            if crawl_options is None
            else {
                "origins": sorted(crawl_options.allowed_origins),
                "maxPages": crawl_options.max_pages,
                "maxDepth": crawl_options.max_depth,
                "maxRequests": crawl_options.max_requests,
                "seedPaths": list(crawl_options.seed_paths),
            },
            agent=None
            if agent_options is None
            else {
                "model": agent_options.model,
                "provider": public_url(agent_options.base_url),
                "maxActions": agent_options.max_actions,
                "maxCalls": agent_options.max_calls,
            },
        ),
        profile="security:"
        + (
            ",".join(
                name
                for enabled, name in (
                    (config.active, "active"),
                    (config.tls_vulnerabilities, "tls-vulnerabilities"),
                    (javascript, "javascript"),
                    (browser_options is not None, "browser"),
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

"""Bounded scan orchestration with deterministic batch result ordering."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from uuid import uuid4

from .checks import PASSIVE_CHECKS, CheckContext
from .checks.active import run_active_checks
from .checks.redirects import check_redirects
from .components import detect_components, inventory_response_is_complete, sanitize_inventory_url
from .config import ScannerConfig
from .http import CollectionError, HttpCollector
from .models import ExposureObservation, Reachability, ScanRun, TargetResult, TargetStatus
from .targets import AddressDenied, NormalizedTarget, normalize_target
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
) -> TargetResult:
    """Scan one explicit target; errors are sanitized and retained on its result."""
    started = datetime.now(UTC)
    http = collector if collector is not None else HttpCollector(config)
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
    active_result = run_active_checks(context, http, enabled=config.active)
    findings.extend(active_result.findings)
    errors.extend(active_result.errors)

    try:
        tls_evidence, tls_findings = tls.scan(effective_target)
        findings.extend(tls_findings)
        errors.extend(tls_evidence.errors)
    except (AddressDenied, OSError, RuntimeError, StopIteration, ValueError):
        errors.append("TLS analysis failed")

    unique = {finding.external_id: finding for finding in findings}
    complete = not errors
    reachability = (
        Reachability.AUTHENTICATED
        if response.body.strip() == _AUTHENTICATED_MARKER_BODY
        else Reachability.REACHABLE
    )
    return TargetResult(
        target=target,
        status=TargetStatus.SUCCESS if complete else TargetStatus.PARTIAL,
        findings=tuple(unique.values()),
        components=detect_components(response),
        exposure=ExposureObservation(
            configured_url=sanitize_inventory_url(target.url) or target.url,
            effective_url=sanitize_inventory_url(response.url),
            reachability=reachability,
            http_status=response.status_code,
            redirect_count=max(0, len(responses) - 1),
            body_length=len(response.body),
        ),
        inventory_complete=inventory_response_is_complete(response),
        errors=tuple(dict.fromkeys(errors)),
        complete=complete,
        started_at=started,
        completed_at=datetime.now(UTC),
    )


def scan_all(
    targets: tuple[NormalizedTarget, ...],
    config: ScannerConfig,
    *,
    progress: ProgressCallback | None = None,
) -> ScanRun:
    """Scan a bounded target list concurrently without cancelling sibling targets."""
    started = datetime.now(UTC)
    completed = 0
    results: list[TargetResult | None] = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        future_indexes = {
            executor.submit(scan_target, target, config): index
            for index, target in enumerate(targets)
        }
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
    )


__all__ = ["ProgressCallback", "scan_all", "scan_target"]

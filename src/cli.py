"""Typer command-line client for scans, reports, storage and SecMan upload."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from .agent import AgentOptions
from .api_inventory import openapi_inventory
from .browser_discovery import BrowserDiscoveryOptions
from .config import load_config
from .crawler import CrawlOptions, allowed_origin, openapi_get_paths
from .evaluation import evaluate
from .external_profile import load_external_profile
from .external_scanners import SUPPORTED_SCANNERS
from .intelligence import load_snapshot, update_snapshot
from .models import ScanRun, Severity, TargetResult, TargetStatus, public_url
from .orchestrator import scan_all
from .reports import render_terminal, write_html, write_json, write_sarif
from .reports.common import atomic_write
from .reports.compare import compare_reports
from .secman import (
    AmbiguousSubject,
    IntegrationClient,
    SecmanIntegrationError,
    targets_from_subjects,
)
from .storage import DatabaseSettings, MariaDbStore, StorageError, connect_database
from .system_review import ReviewOptions, default_prompt_path, load_prompt, review_run
from .targets import NormalizedTarget, TargetError, load_targets, normalize_target
from .traffic import traffic_run
from .visual import VisualOptions, merge_runs, scan_visual_all

app = typer.Typer(
    name="secman-web-check",
    help="Authorized, bounded web-security scanning for explicit targets.",
    no_args_is_help=True,
    rich_help_panel=None,
    context_settings={"max_content_width": 120},
)
db_app = typer.Typer(help="Manage optional MariaDB scan history.")
history_app = typer.Typer(help="Inspect optional MariaDB scan history.")
intel_app = typer.Typer(help="Explicit maintained advisory snapshot updates.")
audit_app = typer.Typer(help="Import Cloudflare security-audit-skill results.")
app.add_typer(intel_app, name="intel")
app.add_typer(audit_app, name="audit")
app.add_typer(db_app, name="db")
app.add_typer(history_app, name="history")
console = Console()
error_console = Console(stderr=True)

_FORMATS = {"terminal", "json", "sarif", "html"}
_DEFAULT_REVIEW_PROMPT = default_prompt_path()
_SEVERITY = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_STATUS_STYLES = {
    TargetStatus.SUCCESS: "green",
    TargetStatus.PARTIAL: "yellow",
    TargetStatus.FAILED: "red",
}


class _ScanProgress:
    """One scan phase on stderr: start line, live bar, and a line per finished target."""

    def __init__(self, label: str, total: int, details: str) -> None:
        noun = "target" if total == 1 else "targets"
        error_console.print(f"[bold]{label}:[/bold] {total} {noun} ({details})")
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=error_console,
            transient=True,
            disable=not error_console.is_interactive,
        )
        self._task = self._progress.add_task(label, total=total)
        self._progress.start()

    def __call__(self, completed: int, total: int, result: TargetResult) -> None:
        duration = (result.completed_at - result.started_at).total_seconds()
        style = _STATUS_STYLES.get(result.status, "white")
        self._progress.console.print(
            f"[dim]\\[{completed}/{total}][/dim] {escape(public_url(result.target.url))} — "
            f"[{style}]{result.status.value}[/{style}] · "
            f"{len(result.findings)} findings · {len(result.errors)} errors · {duration:.1f}s"
        )
        self._progress.update(self._task, completed=completed)

    def close(self) -> None:
        self._progress.stop()


def _database() -> tuple[MariaDbStore, Any]:
    settings = DatabaseSettings.from_environ(os.environ)
    connection = connect_database(settings)
    return MariaDbStore(connection), connection


def _write_reports(run: ScanRun, formats: tuple[str, ...], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not output_dir.is_dir():
        raise ValueError("output directory is not a directory")
    if "terminal" in formats:
        render_terminal(run, console)
    if "json" in formats:
        path = write_json(run, output_dir / f"{run.run_id}.json")
        console.print(f"JSON report: {path}")
    if "sarif" in formats:
        path = write_sarif(run, output_dir / f"{run.run_id}.sarif.json")
        console.print(f"SARIF report: {path}")
    if "html" in formats:
        path = write_html(run, output_dir / f"{run.run_id}.html")
        console.print(f"HTML report: {path}")


def _integration_client() -> IntegrationClient:
    try:
        base_url = os.environ["SECMAN_URL"]
    except KeyError as error:
        raise SecmanIntegrationError("SecMan environment configuration is incomplete") from error
    token = os.environ.get("SECMAN_TOKEN")
    if token:
        return IntegrationClient(base_url, token)
    try:
        return IntegrationClient.login(
            base_url,
            os.environ["SECMAN_USERNAME"],
            os.environ["SECMAN_PASSWORD"],
        )
    except KeyError as error:
        raise SecmanIntegrationError("SecMan credentials are incomplete") from error


def _targets_from_secman(scanner_id: int) -> tuple[NormalizedTarget, ...]:
    with _integration_client() as client:
        return targets_from_subjects(client.list_subjects(scanner_id))


def _push_to_secman(
    run: ScanRun,
    *,
    active: bool,
    scanner_id: int,
    mode: str,
    terminal_coverage: bool = True,
    deferred: bool = False,
) -> None:
    from .delivery import enqueue, queue_path, synchronize
    from .integration_outbox import Outbox
    from .reports.json_report import run_document

    keys = enqueue(
        run_document(run),
        scanner_id,
        mode if not active else "security-extended",
        allow_resolution=terminal_coverage and not active,
    )
    if deferred:
        error_console.print("SecMan delivery queued; use delivery status/retry to synchronize.")
        return
    queue = Outbox(queue_path())
    try:
        rows = synchronize(queue, _integration_client)
        if any(row["state"] != "delivered" for row in rows if row["id"] in keys):
            raise SecmanIntegrationError(
                "SecMan delivery pending or blocked; inspect delivery status"
            )
    finally:
        queue.close()


def _reviewed_snapshot(original: ScanRun, reviewed: ScanRun) -> ScanRun:
    by_url = {public_url(item.target.url): item for item in reviewed.targets}
    targets = []
    for target in original.targets:
        enriched = by_url[public_url(target.target.url)]
        additions = tuple(
            item for item in enriched.findings if item.engine == "secman-web-check-openrouter"
        )
        review_stages = tuple(
            stage for stage in enriched.analysis_stages if stage.name == "system-review"
        )
        review_failed = any(stage.state in {"failed", "cancelled"} for stage in review_stages)
        targets.append(
            replace(
                target,
                findings=(*target.findings, *additions),
                analysis_stages=(*target.analysis_stages, *review_stages),
                complete=False,
                status=TargetStatus.PARTIAL if review_failed else target.status,
                errors=(*target.errors, "System review failed; scan evidence retained")
                if review_failed
                else target.errors,
                completed_at=enriched.completed_at,
            )
        )
    return replace(
        original,
        targets=tuple(targets),
        manifest_json=reviewed.manifest_json,
        completed_at=reviewed.completed_at,
        profile=original.profile + ",review",
    )


def _scanner_id(mode: str, *, combined: bool) -> int:
    variable = {
        "security": "SECMAN_SECURITY_SCANNER_ID",
        "extended": "SECMAN_EXTENDED_SCANNER_ID",
        "visual": "SECMAN_VISUAL_SCANNER_ID",
    }[mode]
    value = os.environ.get(variable)
    if value is None and not combined and mode != "extended":
        value = os.environ.get("SECMAN_SCANNER_ID")
    try:
        scanner_id = int(value or "")
    except ValueError as error:
        suffix = "; combined scans require both mode-specific IDs" if combined else ""
        raise SecmanIntegrationError(f"{variable} is missing or invalid{suffix}") from error
    if scanner_id < 1:
        raise SecmanIntegrationError(f"{variable} must be a positive integer")
    return scanner_id


@app.command()
def scan(
    target: Annotated[
        str | None,
        typer.Argument(help="One authorized HTTP(S) target; HTTPS is assumed without a scheme."),
    ] = None,
    targets_file: Annotated[
        Path | None,
        typer.Option("--targets-file", help="UTF-8 file with one explicit target per line."),
    ] = None,
    targets_csv: Annotated[
        Path | None,
        typer.Option(
            "--targets-csv",
            help="CSV file with the exact header awsAccountNumber,target.",
        ),
    ] = None,
    targets_from_secman: Annotated[
        bool,
        typer.Option(
            "--targets-from-secman",
            help="Use the authorized subjects bound to this scan mode's SecMan scanner.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Abort on the first invalid target line instead of skipping it.",
        ),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="TOML file containing a \\[scan] table."),
    ] = None,
    formats: Annotated[
        list[str] | None,
        typer.Option("--format", "-f", help="Repeat: terminal, json, sarif, html, or all."),
    ] = None,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="Directory for machine-readable reports."),
    ] = Path("scan-output"),
    concurrency: Annotated[
        int | None,
        typer.Option("--concurrency", min=1, help="Maximum number of targets scanned at once."),
    ] = None,
    active: Annotated[
        bool,
        typer.Option("--active", help="Enable the fixed allowlist of bounded active probes."),
    ] = False,
    dirbuster: Annotated[
        bool,
        typer.Option(
            "--dirbuster",
            help="Explicitly enable bounded, non-recursive path discovery on HTTP 200 targets.",
        ),
    ] = False,
    crawl: Annotated[
        bool,
        typer.Option("--crawl", help="Follow public HTML links within a bounded origin scope."),
    ] = False,
    allowed_origins: Annotated[
        list[str] | None,
        typer.Option(
            "--allowed-origin",
            help="Additional HTTP(S) origin allowed for crawling, script inventory or browser resources.",
        ),
    ] = None,
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", min=1, help="Maximum pages per crawled target."),
    ] = 50,
    max_depth: Annotated[
        int,
        typer.Option("--max-depth", min=0, help="Maximum link depth from the target page."),
    ] = 2,
    max_requests: Annotated[
        int,
        typer.Option("--max-requests", min=1, help="Maximum crawl requests per target."),
    ] = 200,
    api_spec: Annotated[
        Path | None,
        typer.Option(
            "--api-spec", help="Local OpenAPI JSON file with public GET paths for crawling."
        ),
    ] = None,
    ai_agent: Annotated[
        bool,
        typer.Option("--ai-agent", help="Let OpenRouter sequence approved active checks."),
    ] = False,
    external_scanner: Annotated[
        list[str] | None,
        typer.Option(
            "--external-scanner",
            help="Explicitly run a safe profile: nuclei or nikto (repeatable).",
        ),
    ] = None,
    javascript_inventory: Annotated[
        bool,
        typer.Option(
            "--javascript-inventory",
            help="Fetch referenced JavaScript, retain SHA-256 and metadata, and discard bytes.",
        ),
    ] = False,
    llm_review: Annotated[
        bool,
        typer.Option(
            "--llm-review",
            help="Explicitly send sanitized scan evidence to OpenRouter for system review.",
        ),
    ] = False,
    llm_prompt: Annotated[
        Path,
        typer.Option(
            "--llm-prompt",
            help="UTF-8 system-prompt file used by the optional OpenRouter review.",
        ),
    ] = _DEFAULT_REVIEW_PROMPT,
    scan_mode: Annotated[
        str,
        typer.Option(
            "--scan-mode",
            help="Select security, visual, or both scanning approaches.",
        ),
    ] = "security",
    visual_no_ai: Annotated[
        bool,
        typer.Option(
            "--visual-no-ai",
            help="Capture screenshots without vision-model finding analysis.",
        ),
    ] = False,
    visual_output_dir: Annotated[
        Path | None,
        typer.Option(
            "--visual-output-dir",
            help="Screenshot directory (default: OUTPUT_DIR/screenshots).",
        ),
    ] = None,
    visual_redacted_crops: Annotated[
        Path | None,
        typer.Option(
            "--visual-redacted-crops",
            help="Directory of operator-reviewed PNG crops for OpenRouter; filenames match screenshots.",
        ),
    ] = None,
    allow_private_targets: Annotated[
        bool,
        typer.Option(
            "--allow-private-targets",
            help="Allow authorized RFC1918/ULA targets; loopback and link-local remain denied.",
        ),
    ] = False,
    external_profile_path: Annotated[
        Path | None,
        typer.Option(
            "--external-profile",
            rich_help_panel="External engines",
            help="Reviewed external binary/template manifest.",
        ),
    ] = None,
    external_profile_sha256: Annotated[
        str | None,
        typer.Option(
            "--external-profile-sha256",
            rich_help_panel="External engines",
            help="Trusted external manifest SHA-256.",
        ),
    ] = None,
    tls_vulnerabilities: Annotated[
        bool,
        typer.Option(
            "--tls-vulnerabilities",
            help="Opt in to TLS vulnerability probes beyond certificate/protocol inventory.",
        ),
    ] = False,
    browser_discovery: Annotated[
        bool,
        typer.Option(
            "--browser-discovery", help="Discover rendered links and read-only browser API traffic."
        ),
    ] = False,
    advisory_db: Annotated[
        Path | None, typer.Option("--advisory-db", help="Offline maintained OSV snapshot.")
    ] = None,
    advisory_sha256: Annotated[
        str | None,
        typer.Option("--advisory-sha256", help="Trusted SHA-256 of the advisory snapshot."),
    ] = None,
    requests_per_second: Annotated[
        float | None,
        typer.Option("--requests-per-second", rich_help_panel="Traffic limits", min=0.01),
    ] = None,
    global_requests_per_second: Annotated[
        float | None,
        typer.Option("--global-requests-per-second", rich_help_panel="Traffic limits", min=0.01),
    ] = None,
    per_origin_concurrency: Annotated[
        int | None,
        typer.Option("--per-origin-concurrency", rich_help_panel="Traffic limits", min=1),
    ] = None,
    max_operations: Annotated[
        int | None, typer.Option("--max-operations", rich_help_panel="Traffic limits", min=1)
    ] = None,
    max_provider_calls: Annotated[
        int | None, typer.Option("--max-provider-calls", rich_help_panel="Traffic limits", min=1)
    ] = None,
    store_db: Annotated[
        bool,
        typer.Option("--store-db", help="Persist this run to explicitly configured MariaDB."),
    ] = False,
    push_to_secman: Annotated[
        bool,
        typer.Option(
            "--push-to-secman", help="Submit atomic target snapshots through SecMan REST v1."
        ),
    ] = False,
    defer_secman: Annotated[
        bool, typer.Option("--defer-secman", help="Queue upload without contacting SecMan.")
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on", help="Exit 1 at this severity: info, low, medium, high, critical, none."
        ),
    ] = "high",
) -> None:
    """Scan one target or a target file and produce normalized reports."""
    if (
        sum(
            (
                target is not None,
                targets_file is not None,
                targets_csv is not None,
                targets_from_secman,
            )
        )
        != 1
    ):
        raise typer.BadParameter(
            "provide exactly one target, --targets-file, --targets-csv, or --targets-from-secman"
        )
    if defer_secman and not push_to_secman:
        raise typer.BadParameter("--defer-secman requires --push-to-secman")
    scan_mode = scan_mode.lower()
    if scan_mode not in {"security", "visual", "both"}:
        raise typer.BadParameter("--scan-mode must be security, visual, or both")
    selected_scanners = tuple(name.lower() for name in (external_scanner or ()))
    unknown_scanners = set(selected_scanners) - SUPPORTED_SCANNERS
    if unknown_scanners:
        raise typer.BadParameter(
            f"--external-scanner must be nuclei or nikto, not {min(unknown_scanners)}"
        )
    if (
        dirbuster
        or selected_scanners
        or crawl
        or ai_agent
        or javascript_inventory
        or browser_discovery
        or tls_vulnerabilities
        or advisory_db
    ) and scan_mode == "visual":
        raise typer.BadParameter(
            "discovery, external scanners, AI agent and JavaScript inventory require a security scan"
        )
    if (
        allowed_origins
        and not crawl
        and not browser_discovery
        and not javascript_inventory
        and scan_mode == "security"
    ):
        raise typer.BadParameter(
            "--allowed-origin requires crawl, script inventory, browser discovery or visual mode"
        )
    if api_spec is not None and not crawl:
        raise typer.BadParameter("--api-spec requires --crawl")
    try:
        crawl_options = (
            CrawlOptions(
                allowed_origins=frozenset(allowed_origin(value) for value in allowed_origins or ()),
                max_pages=max_pages,
                max_depth=max_depth,
                max_requests=max_requests,
                seed_paths=openapi_get_paths(api_spec) if api_spec is not None else (),
            )
            if crawl
            else None
        )
    except (OSError, TargetError, TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    requested = tuple(formats or ("terminal",))
    if "all" in requested:
        requested = ("terminal", "json", "sarif", "html")
    unknown = set(requested) - _FORMATS
    if unknown:
        raise typer.BadParameter(f"unknown report format: {min(unknown)}")
    threshold_name = fail_on.upper()
    if threshold_name != "NONE" and threshold_name not in Severity.__members__:
        raise typer.BadParameter("--fail-on must be info, low, medium, high, critical, or none")
    review_options: ReviewOptions | None = None
    try:
        scan_config = load_config(
            config,
            os.environ,
            concurrency=concurrency,
            tls_vulnerabilities=True if tls_vulnerabilities else None,
            requests_per_second=requests_per_second,
            global_requests_per_second=global_requests_per_second,
            per_origin_concurrency=per_origin_concurrency,
            max_operations=max_operations,
            max_provider_calls=max_provider_calls,
            active=True if active else None,
            allow_private_targets=True if allow_private_targets else None,
        )
        if ai_agent and not scan_config.active:
            raise typer.BadParameter("--ai-agent requires --active for approved check actions")
        agent_options = (
            AgentOptions(
                api_key=os.environ.get("SECMAN_AI_API_KEY", ""),
                model=os.environ.get("SECMAN_AI_MODEL", "anthropic/claude-sonnet-4.5"),
                base_url=os.environ.get("SECMAN_AI_BASE_URL", "https://openrouter.ai/api/v1"),
            )
            if ai_agent
            else None
        )
        if selected_scanners and not (external_profile_path and external_profile_sha256):
            raise ValueError(
                "External scanners require --external-profile and --external-profile-sha256"
            )
        reviewed_profile = (
            load_external_profile(external_profile_path, external_profile_sha256)
            if external_profile_path and external_profile_sha256
            else None
        )
        if bool(advisory_db) != bool(advisory_sha256):
            raise ValueError("--advisory-db and --advisory-sha256 must be supplied together")
        snapshot = (
            load_snapshot(advisory_db, advisory_sha256) if advisory_db and advisory_sha256 else None
        )
        declared_operations = openapi_inventory(api_spec) if api_spec else ()
        browser_options = (
            BrowserDiscoveryOptions(
                frozenset(allowed_origin(value) for value in allowed_origins or ()),
                max_pages,
                max_depth,
            )
            if browser_discovery
            else None
        )
        extended = bool(
            scan_config.active
            or scan_config.tls_vulnerabilities
            or dirbuster
            or selected_scanners
            or crawl
            or ai_agent
            or javascript_inventory
            or llm_review
            or browser_discovery
        )
        if push_to_secman:
            if scan_mode in {"security", "both"}:
                _scanner_id("extended" if extended else "security", combined=scan_mode == "both")
            if scan_mode in {"visual", "both"}:
                _scanner_id("visual", combined=scan_mode == "both")
        if llm_review:
            load_prompt(llm_prompt)
            review_options = ReviewOptions(
                prompt_path=llm_prompt,
                api_key=os.environ.get("OPENROUTER_API_KEY", ""),
                model=os.environ.get("SECMAN_OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5"),
                base_url=os.environ.get(
                    "SECMAN_OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
                ),
            )
        if targets_from_secman:
            source_mode = (
                "visual" if scan_mode == "visual" else ("extended" if extended else "security")
            )
            error_console.print("[dim]Fetching authorized subjects from SecMan…[/dim]")
            targets = _targets_from_secman(_scanner_id(source_mode, combined=scan_mode == "both"))
        else:
            loaded_targets = load_targets(target, targets_file, targets_csv, strict=strict)
            targets = loaded_targets.targets
            for skipped in loaded_targets.skipped:
                error_console.print(f"[yellow]Skipped invalid target[/yellow]: {skipped.reason}")
    except (OSError, TypeError, ValueError, TargetError, SecmanIntegrationError) as error:
        raise typer.BadParameter(str(error)) from error
    if not targets:
        raise typer.BadParameter("no usable targets were supplied")
    if selected_scanners and any(
        item.url != public_url(item.url) or urlsplit(item.url).path != "/" for item in targets
    ):
        raise typer.BadParameter(
            "External scanners require explicit origin-root targets without queries"
        )

    visual_options = None
    if scan_mode in {"visual", "both"}:
        try:
            visual_options = VisualOptions(
                output_dir=visual_output_dir or output_dir / "screenshots",
                analyze=not visual_no_ai,
                api_key=os.environ.get("SECMAN_VISION_API_KEY"),
                model=os.environ.get("SECMAN_VISION_MODEL", "anthropic/claude-sonnet-4.5"),
                base_url=os.environ.get("SECMAN_VISION_BASE_URL", "https://openrouter.ai/api/v1"),
                allowed_origins=frozenset(allowed_origin(value) for value in allowed_origins or ()),
                redacted_crops=visual_redacted_crops,
            )
        except ValueError as error:
            raise typer.BadParameter(str(error)) from error

    with traffic_run(scan_config) as traffic:
        security_run: ScanRun | None = None
        if scan_mode in {"security", "both"}:
            security_progress = _ScanProgress(
                "Security scan",
                len(targets),
                f"concurrency {scan_config.concurrency}, "
                f"{'active' if scan_config.active else 'passive'} mode",
            )
            try:
                if (
                    browser_options is not None
                    or snapshot is not None
                    or dirbuster
                    or selected_scanners
                    or javascript_inventory
                    or crawl_options is not None
                    or agent_options is not None
                ):
                    security_run = scan_all(
                        targets,
                        scan_config,
                        progress=security_progress,
                        dirbuster=dirbuster,
                        external_scanners=selected_scanners,
                        external_profile=reviewed_profile,
                        crawl_options=crawl_options,
                        agent_options=agent_options,
                        javascript=javascript_inventory,
                        script_origins=frozenset(
                            allowed_origin(value) for value in allowed_origins or ()
                        ),
                        traffic=traffic,
                        browser_options=browser_options,
                        api_operations=declared_operations,
                        advisory_snapshot=snapshot,
                    )
                else:
                    security_run = scan_all(
                        targets, scan_config, progress=security_progress, traffic=traffic
                    )
            finally:
                security_progress.close()
        visual_run: ScanRun | None = None
        if visual_options is not None:
            visual_progress = _ScanProgress(
                "Visual scan",
                len(targets),
                f"concurrency {scan_config.concurrency}, "
                f"vision analysis {'on' if visual_options.analyze else 'off'}",
            )
            try:
                visual_run = scan_visual_all(
                    targets, scan_config, visual_options, progress=visual_progress, traffic=traffic
                )
            except (OSError, RuntimeError, ValueError) as error:
                error_console.print(f"[red]Operational error:[/red] {error}")
                raise typer.Exit(2) from error
            finally:
                visual_progress.close()
        run: ScanRun | None
        if security_run is not None and visual_run is not None:
            run = merge_runs(security_run, visual_run)
        else:
            run = security_run or visual_run
        if run is None:  # pragma: no cover - guarded by scan_mode validation
            raise typer.Exit(2)
        if llm_review:
            _write_reports(run, requested, output_dir)
            try:
                if review_options is None:  # pragma: no cover - initialized with llm_review
                    raise RuntimeError("system review configuration is unavailable")
                error_console.print("[dim]Reviewing sanitized evidence with OpenRouter…[/dim]")
                run = review_run(run, review_options, traffic=traffic)
                if security_run is not None:
                    security_run = _reviewed_snapshot(security_run, run)
                elif visual_run is not None:
                    visual_run = _reviewed_snapshot(visual_run, run)
            except (httpx.HTTPError, OSError, RuntimeError, TypeError, ValueError) as error:
                error_console.print(f"[red]Operational error:[/red] {error}")
                raise typer.Exit(2) from error
        run = replace(run, metrics_json=json.dumps(traffic.metrics(), sort_keys=True))
        operational_failure = any(
            result.status in {TargetStatus.PARTIAL, TargetStatus.FAILED} for result in run.targets
        )
        try:
            _write_reports(run, requested, output_dir)
            if push_to_secman:
                _write_reports(run, ("json",), output_dir)
            if (
                security_run is not None
                and visual_run is not None
                and (push_to_secman or "json" in requested)
            ):
                write_json(security_run, output_dir / f"{run.run_id}-security.json")
                write_json(visual_run, output_dir / f"{run.run_id}-visual.json")
            if store_db and not traffic.cancelled:
                error_console.print("[dim]Storing run in MariaDB…[/dim]")
                try:
                    store, connection = _database()
                    try:
                        store.save(run)
                    finally:
                        connection.close()
                except (StorageError, OSError, ValueError):
                    operational_failure = True
                    error_console.print("MariaDB persistence failed; local report retained.")
            if push_to_secman and not traffic.cancelled:
                combined = scan_mode == "both"
                for scan_snapshot, mode in (
                    (security_run, "security-extended" if extended else "security"),
                    (visual_run, "visual"),
                ):
                    if scan_snapshot is None:
                        continue
                    try:
                        _push_to_secman(
                            scan_snapshot,
                            active=scan_config.active if mode != "visual" else False,
                            scanner_id=_scanner_id(
                                "extended" if mode == "security-extended" else mode,
                                combined=combined,
                            ),
                            mode=mode,
                            terminal_coverage=mode == "security",
                            deferred=defer_secman,
                        )
                    except (SecmanIntegrationError, OSError, ValueError):
                        operational_failure = True
                        error_console.print(
                            f"{mode} synchronization failed; report/queue retained. Use delivery status."
                        )
        except (
            AmbiguousSubject,
            OSError,
            SecmanIntegrationError,
            StorageError,
            ValueError,
        ) as error:
            error_console.print(f"[red]Operational error:[/red] {error}")
            raise typer.Exit(2) from error
        if operational_failure:
            raise typer.Exit(2)
        if threshold_name != "NONE":
            threshold = _SEVERITY[Severity[threshold_name]]
            if any(
                _SEVERITY[finding.severity] >= threshold
                for result in run.targets
                for finding in result.findings
            ):
                raise typer.Exit(1)


@app.command()
def compare(
    old: Annotated[Path, typer.Argument(help="Earlier local JSON report.")],
    new: Annotated[Path, typer.Argument(help="Later local JSON report.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Print machine-readable comparison JSON.")
    ] = False,
) -> None:
    """Compare stable finding IDs without claiming resolution from partial coverage."""
    try:
        result = compare_reports(old, new)
    except (OSError, TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if json_output:
        typer.echo(json.dumps(result, sort_keys=True))
        return
    console.print(
        f"[bold]Comparison[/bold] {escape(str(result['oldRunId']))} "
        f"→ {escape(str(result['newRunId']))}"
    )
    for name in ("introduced", "resolved", "unconfirmedAbsent"):
        console.print(f"{name}: {len(result[name])}")
    console.print(f"unchanged: {result['unchangedCount']}")


@audit_app.command("import")
def audit_import(
    findings_file: Annotated[Path, typer.Argument(help="findings.json from the audit skill.")],
    target: Annotated[
        str | None, typer.Option("--target", help="Deployed URL the audited code belongs to.")
    ] = None,
    commit_sha: Annotated[str | None, typer.Option("--commit-sha")] = None,
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", case_sensitive=False)
    ] = Severity.INFO,
    include_needs_validation: Annotated[bool, typer.Option("--include-needs-validation")] = False,
    include_exploit_detail: Annotated[
        bool,
        typer.Option("--include-exploit-detail", help="Include payloads and reproduction steps."),
    ] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Write normalized JSON.")] = None,
    push_to_github: Annotated[bool, typer.Option("--push-to-github")] = False,
    github_repo: Annotated[str | None, typer.Option("--github-repo", help="owner/name")] = None,
    allow_public_repo: Annotated[bool, typer.Option("--allow-public-repo")] = False,
    max_issues: Annotated[int, typer.Option("--max-issues", min=1, max=100)] = 25,
    push_to_secman: Annotated[bool, typer.Option("--push-to-secman")] = False,
    scanner_id: Annotated[
        int | None, typer.Option("--scanner-id", help="Defaults to SECMAN_AUDIT_SCANNER_ID.")
    ] = None,
) -> None:
    """Normalize audit findings; optionally open GitHub issues and upload to SecMan.

    Without --push-to-* flags this is a local dry run. GitHub issues are created first so
    SecMan findings can link to them. Uploads never resolve older findings.
    """
    from .code_audit import (
        AuditError,
        GithubIssueClient,
        build_audit_run_body,
        load_audit_findings,
        publish_github_issues,
    )

    try:
        findings = load_audit_findings(
            findings_file,
            include_needs_validation=include_needs_validation,
            min_severity=min_severity,
            include_exploit_detail=include_exploit_detail,
        )
        issue_urls: dict[str, str] = {}
        if push_to_github:
            if not github_repo:
                raise AuditError("--github-repo is required with --push-to-github")
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
            with GithubIssueClient(github_repo, token) as github:
                issue_urls = publish_github_issues(
                    github,
                    findings,
                    commit_sha=commit_sha,
                    allow_public=allow_public_repo,
                    max_issues=max_issues,
                )
        if push_to_secman:
            if not target:
                raise AuditError("--target is required with --push-to-secman")
            normalized = normalize_target(target)
            sid = (
                scanner_id
                if scanner_id is not None
                else _scanner_id_from_env("SECMAN_AUDIT_SCANNER_ID")
            )
            with _integration_client() as client:
                from .secman import match_subject

                subject = match_subject(client.list_subjects(sid), normalized.url)
                if subject is None:
                    raise SecmanIntegrationError("no authorized SecMan subject matches --target")
                client.submit_run(
                    build_audit_run_body(
                        sid,
                        subject,
                        findings,
                        target_url=normalized.url,
                        commit_sha=commit_sha,
                        issue_urls=issue_urls,
                    )
                )
        if output is not None:
            atomic_write(
                output,
                json.dumps(
                    [f.to_dict() | {"issueUrl": issue_urls.get(f.fingerprint)} for f in findings],
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
            )
    except (AuditError, SecmanIntegrationError, TargetError, OSError) as error:
        error_console.print(f"[red]Audit import failed:[/red] {escape(str(error))}")
        raise typer.Exit(2) from error
    table = Table("Severity", "Verdict", "Location", "Title", "Issue")
    for item in findings:
        table.add_row(
            item.severity.value,
            item.verdict,
            item.location,
            escape(item.title),
            issue_urls.get(item.fingerprint, ""),
        )
    console.print(table)
    console.print(
        f"{len(findings)} finding(s); github={'yes' if push_to_github else 'no'} "
        f"secman={'yes' if push_to_secman else 'no'}"
    )


def _scanner_id_from_env(variable: str) -> int:
    try:
        value = int(os.environ.get(variable, ""))
    except ValueError as error:
        raise SecmanIntegrationError(f"{variable} is missing or invalid") from error
    if value < 1:
        raise SecmanIntegrationError(f"{variable} must be a positive integer")
    return value


@db_app.command("install")
def db_install() -> None:
    """Create or validate the optional MariaDB schema."""
    try:
        store, connection = _database()
        try:
            store.install()
        finally:
            connection.close()
    except StorageError as error:
        error_console.print(f"[red]{error}[/red]")
        raise typer.Exit(2) from error
    console.print("MariaDB schema is installed and current.")


@db_app.command("status")
def db_status() -> None:
    """Show the optional MariaDB schema status."""
    try:
        store, connection = _database()
        try:
            status = store.status()
        finally:
            connection.close()
    except StorageError as error:
        error_console.print(f"[red]{error}[/red]")
        raise typer.Exit(2) from error
    if not status.installed:
        console.print("MariaDB schema is not installed.")
        raise typer.Exit(2)
    console.print(f"MariaDB schema version: {status.version}")


@history_app.command("list")
def history_list(
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 50,
) -> None:
    """List recently stored runs from MariaDB."""
    try:
        store, connection = _database()
        try:
            runs = store.list_runs(limit)
        finally:
            connection.close()
    except StorageError as error:
        error_console.print(f"[red]{error}[/red]")
        raise typer.Exit(2) from error
    table = Table("Run", "Started", "Targets", "Findings", "Components")
    for run in runs:
        table.add_row(
            run.run_id,
            run.started_at.isoformat(),
            str(run.target_count),
            str(run.finding_count),
            str(run.component_count),
        )
    console.print(table)


@app.command("evaluate")
def evaluate_command(
    corpus: Annotated[Path, typer.Argument(help="Synthetic vulnerable/safe response corpus JSON.")],
    output: Annotated[Path, typer.Option("--output", help="Detection measurements JSON.")],
) -> None:
    """Measure class-level precision/recall without any target requests."""
    try:
        result = evaluate(corpus)
        atomic_write(output, json.dumps(result, indent=2, sort_keys=True) + "\n")
    except (OSError, TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print(f"Measurements: {output}")
    if not result["passed"]:
        raise typer.Exit(1)


@intel_app.command("update")
def intel_update(
    output: Annotated[Path, typer.Option("--output", help="Normalized offline snapshot path.")],
    advisory: Annotated[
        list[str] | None, typer.Option("--advisory", help="OSV advisory ID, repeatable.")
    ] = None,
    package: Annotated[
        list[str] | None,
        typer.Option(
            "--package", help="Supported npm package, repeatable; discovers new advisories."
        ),
    ] = None,
) -> None:
    """Explicitly fetch selected public OSV records; no target inventory is transmitted."""
    try:
        digest = update_snapshot(tuple(advisory or ()), output, packages=tuple(package or ()))
    except (httpx.HTTPError, OSError, RuntimeError, TypeError, ValueError) as error:
        error_console.print(f"[red]Advisory update failed:[/red] {error}")
        raise typer.Exit(2) from error
    console.print(f"Snapshot: {output}\nSHA-256: {digest}")


@history_app.command("export")
def history_export(
    run_id: Annotated[str, typer.Argument(help="Stored run UUID.")],
    output: Annotated[Path, typer.Option("--output", help="Destination JSON file.")],
) -> None:
    """Export a full archived JSON report; older summary-only runs fail explicitly."""
    try:
        store, connection = _database()
        try:
            document = store.export(run_id)
        finally:
            connection.close()
        atomic_write(output, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    except (OSError, StorageError, ValueError) as error:
        error_console.print(f"[red]Export failed:[/red] {error}")
        raise typer.Exit(2) from error
    console.print(f"JSON report: {output}")


@app.command("delivery")
def delivery_command(
    action: Annotated[str, typer.Argument(help="status, retry, upload, or quarantine")],
    report: Annotated[Path | None, typer.Option("--report")] = None,
    scanner_id: Annotated[int | None, typer.Option("--scanner-id")] = None,
    mode: Annotated[str, typer.Option("--mode")] = "security",
    defer: Annotated[bool, typer.Option("--defer")] = False,
    resume_blocked: Annotated[bool, typer.Option("--resume-blocked")] = False,
    delivery_id: Annotated[str | None, typer.Option("--delivery-id")] = None,
) -> None:
    """Upload a saved JSON report or recover durable deliveries without rescanning."""
    from .delivery import enqueue, queue_path, synchronize
    from .integration_outbox import DeliveryError, Outbox

    if action not in {"status", "retry", "upload", "quarantine"} or mode not in {
        "security",
        "security-extended",
        "visual",
    }:
        raise typer.BadParameter("Choose status/retry/upload/quarantine and a supported mode")
    try:
        if action == "upload":
            if report is None or scanner_id is None or report.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("A bounded JSON report and scanner ID are required")
            enqueue(json.loads(report.read_text()), scanner_id, mode)
        queue = Outbox(queue_path())
        try:
            if action == "quarantine":
                if not delivery_id:
                    raise ValueError("--delivery-id is required")
                queue.quarantine(delivery_id)
                rows = queue.status()
            elif action != "status" and not defer:
                rows = synchronize(queue, _integration_client, resume=resume_blocked)
            else:
                rows = queue.status()
        finally:
            queue.close()
        typer.echo(json.dumps(rows))
        if (
            action in {"retry", "upload"}
            and not defer
            and any(row["state"] not in {"delivered", "quarantined"} for row in rows)
        ):
            raise typer.Exit(2)
    except (DeliveryError, ValueError, OSError):
        error_console.print("Delivery failed; inspect retained queue and configuration.")
        raise typer.Exit(2) from None


if __name__ == "__main__":
    app()

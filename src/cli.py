"""Typer command-line client for scans, reports, storage and SecMan upload."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

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

from .config import load_config
from .models import ScanRun, Severity, TargetResult, TargetStatus
from .orchestrator import scan_all
from .reports import render_terminal, write_html, write_json, write_sarif
from .secman import (
    AmbiguousSubject,
    IntegrationClient,
    SecmanIntegrationError,
    build_run_body,
    match_subject,
    targets_from_subjects,
)
from .storage import DatabaseSettings, MariaDbStore, StorageError, connect_database
from .targets import NormalizedTarget, TargetError, load_targets
from .visual import VisualOptions, merge_runs, scan_visual_all

app = typer.Typer(
    name="secman-web-check",
    help="Authorized, bounded web-security scanning for explicit targets.",
    no_args_is_help=True,
)
db_app = typer.Typer(help="Manage optional MariaDB scan history.")
history_app = typer.Typer(help="Inspect optional MariaDB scan history.")
app.add_typer(db_app, name="db")
app.add_typer(history_app, name="history")
console = Console()
error_console = Console(stderr=True)

_FORMATS = {"terminal", "json", "sarif", "html"}
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
            f"[dim]\\[{completed}/{total}][/dim] {escape(result.target.url)} — "
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


def _push_to_secman(run: ScanRun, *, active: bool, scanner_id: int, mode: str) -> None:
    with _integration_client() as client:
        subjects = client.list_subjects(scanner_id)
        subjects_by_id = {subject.id: subject for subject in subjects}
        failed_hosts: list[str] = []
        for result in run.targets:
            try:
                subject = None
                if result.target.secman_subject_id is not None:
                    candidate = subjects_by_id.get(result.target.secman_subject_id)
                    if (
                        candidate is not None
                        and candidate.asset_id == result.target.secman_asset_id
                    ):
                        subject = candidate
                    elif result.target.secman_asset_id is not None:
                        asset_matches = [
                            item
                            for item in subjects
                            if item.asset_id == result.target.secman_asset_id
                        ]
                        if len(asset_matches) == 1:
                            subject = asset_matches[0]
                        elif len(asset_matches) > 1:
                            raise SecmanIntegrationError(
                                "multiple SecMan subjects match the bound asset"
                            )
                else:
                    subject = match_subject(
                        subjects,
                        result.target.url,
                        aws_account_number=result.target.aws_account_number,
                    )
                if subject is None:
                    message = (
                        "SecMan target binding changed during the scan"
                        if result.target.secman_subject_id is not None
                        else "no authorized subject matched"
                    )
                    raise SecmanIntegrationError(message)
                body = build_run_body(
                    scanner_id,
                    subject,
                    result,
                    metadata={
                        "scannerVersion": "0.2.0",
                        "scanMode": mode,
                        "securityMode": "active" if active else "passive",
                        "awsAccountNumber": result.target.aws_account_number,
                    },
                )
                client.submit_run(body)
            except (AmbiguousSubject, SecmanIntegrationError):
                failed_hosts.append(result.target.host)
        if failed_hosts:
            raise SecmanIntegrationError(
                "SecMan upload failed for: " + ", ".join(sorted(set(failed_hosts)))
            )


def _scanner_id(mode: str, *, combined: bool) -> int:
    variable = "SECMAN_SECURITY_SCANNER_ID" if mode == "security" else "SECMAN_VISUAL_SCANNER_ID"
    value = os.environ.get(variable)
    if value is None and not combined:
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
    allow_private_targets: Annotated[
        bool,
        typer.Option(
            "--allow-private-targets",
            help="Allow authorized RFC1918/ULA targets; loopback and link-local remain denied.",
        ),
    ] = False,
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
    scan_mode = scan_mode.lower()
    if scan_mode not in {"security", "visual", "both"}:
        raise typer.BadParameter("--scan-mode must be security, visual, or both")
    requested = tuple(formats or ("terminal",))
    if "all" in requested:
        requested = ("terminal", "json", "sarif", "html")
    unknown = set(requested) - _FORMATS
    if unknown:
        raise typer.BadParameter(f"unknown report format: {min(unknown)}")
    threshold_name = fail_on.upper()
    if threshold_name != "NONE" and threshold_name not in Severity.__members__:
        raise typer.BadParameter("--fail-on must be info, low, medium, high, critical, or none")
    try:
        scan_config = load_config(
            config,
            os.environ,
            concurrency=concurrency,
            active=True if active else None,
            allow_private_targets=True if allow_private_targets else None,
        )
        if targets_from_secman:
            source_mode = "visual" if scan_mode == "visual" else "security"
            error_console.print("[dim]Fetching authorized subjects from SecMan…[/dim]")
            targets = _targets_from_secman(_scanner_id(source_mode, combined=scan_mode == "both"))
        else:
            loaded_targets = load_targets(target, targets_file, targets_csv, strict=strict)
            targets = loaded_targets.targets
            for skipped in loaded_targets.skipped:
                error_console.print(
                    f"[yellow]Skipped invalid target[/yellow] {skipped.value!r}: {skipped.reason}"
                )
    except (OSError, TypeError, ValueError, TargetError, SecmanIntegrationError) as error:
        raise typer.BadParameter(str(error)) from error
    if not targets:
        raise typer.BadParameter("no usable targets were supplied")

    visual_options = None
    if scan_mode in {"visual", "both"}:
        try:
            visual_options = VisualOptions(
                output_dir=visual_output_dir or output_dir / "screenshots",
                analyze=not visual_no_ai,
                api_key=os.environ.get("SECMAN_VISION_API_KEY"),
                model=os.environ.get("SECMAN_VISION_MODEL", "anthropic/claude-sonnet-4.5"),
                base_url=os.environ.get("SECMAN_VISION_BASE_URL", "https://openrouter.ai/api/v1"),
            )
        except ValueError as error:
            raise typer.BadParameter(str(error)) from error

    security_run: ScanRun | None = None
    if scan_mode in {"security", "both"}:
        security_progress = _ScanProgress(
            "Security scan",
            len(targets),
            f"concurrency {scan_config.concurrency}, "
            f"{'active' if scan_config.active else 'passive'} mode",
        )
        try:
            security_run = scan_all(targets, scan_config, progress=security_progress)
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
                targets, scan_config, visual_options, progress=visual_progress
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
    operational_failure = any(
        result.status in {TargetStatus.PARTIAL, TargetStatus.FAILED} for result in run.targets
    )
    try:
        _write_reports(run, requested, output_dir)
        if store_db:
            error_console.print("[dim]Storing run in MariaDB…[/dim]")
            store, connection = _database()
            try:
                store.save(run)
            finally:
                connection.close()
        if push_to_secman:
            combined = scan_mode == "both"
            if security_run is not None:
                error_console.print(
                    f"[dim]Pushing {len(security_run.targets)} security "
                    "snapshot(s) to SecMan…[/dim]"
                )
                _push_to_secman(
                    security_run,
                    active=scan_config.active,
                    scanner_id=_scanner_id("security", combined=combined),
                    mode="security",
                )
            if visual_run is not None:
                error_console.print(
                    f"[dim]Pushing {len(visual_run.targets)} visual snapshot(s) to SecMan…[/dim]"
                )
                _push_to_secman(
                    visual_run,
                    active=False,
                    scanner_id=_scanner_id("visual", combined=combined),
                    mode="visual",
                )
    except (AmbiguousSubject, OSError, SecmanIntegrationError, StorageError, ValueError) as error:
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


if __name__ == "__main__":
    app()

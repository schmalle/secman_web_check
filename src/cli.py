"""Typer command-line client for scans, reports, storage and SecMan upload."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from .config import load_config
from .models import ScanRun, Severity, TargetStatus
from .orchestrator import scan_all
from .reports import render_terminal, write_html, write_json, write_sarif
from .secman import (
    AmbiguousSubject,
    IntegrationClient,
    SecmanIntegrationError,
    build_run_body,
    match_subject,
)
from .storage import DatabaseSettings, MariaDbStore, StorageError, connect_database
from .targets import TargetError, load_targets

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


def _push_to_secman(run: ScanRun, *, active: bool) -> None:
    try:
        base_url = os.environ["SECMAN_URL"]
        scanner_id = int(os.environ["SECMAN_SCANNER_ID"])
    except (KeyError, ValueError) as error:
        raise SecmanIntegrationError("SecMan environment configuration is incomplete") from error
    token = os.environ.get("SECMAN_TOKEN")
    if token:
        client = IntegrationClient(base_url, token)
    else:
        try:
            client = IntegrationClient.login(
                base_url,
                os.environ["SECMAN_USERNAME"],
                os.environ["SECMAN_PASSWORD"],
            )
        except KeyError as error:
            raise SecmanIntegrationError("SecMan credentials are incomplete") from error
    with client:
        subjects = client.list_subjects(scanner_id)
        failed_hosts: list[str] = []
        for result in run.targets:
            try:
                subject = match_subject(subjects, result.target.url)
                if subject is None:
                    raise SecmanIntegrationError("no authorized subject matched")
                body = build_run_body(
                    scanner_id,
                    subject,
                    result,
                    metadata={
                        "scannerVersion": "0.1.0",
                        "mode": "active" if active else "passive",
                    },
                )
                client.submit_run(body)
            except (AmbiguousSubject, SecmanIntegrationError):
                failed_hosts.append(result.target.host)
        if failed_hosts:
            raise SecmanIntegrationError(
                "SecMan upload failed for: " + ", ".join(sorted(set(failed_hosts)))
            )


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
    config: Annotated[
        Path | None,
        typer.Option("--config", help="TOML file containing a [scan] table."),
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
    if (target is None) == (targets_file is None):
        raise typer.BadParameter("provide exactly one target or --targets-file")
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
        targets = load_targets(target, targets_file)
    except (OSError, TypeError, ValueError, TargetError) as error:
        raise typer.BadParameter(str(error)) from error
    if not targets:
        raise typer.BadParameter("no usable targets were supplied")

    run = scan_all(targets, scan_config)
    operational_failure = any(
        result.status in {TargetStatus.PARTIAL, TargetStatus.FAILED} for result in run.targets
    )
    try:
        _write_reports(run, requested, output_dir)
        if store_db:
            store, connection = _database()
            try:
                store.save(run)
            finally:
                connection.close()
        if push_to_secman:
            _push_to_secman(run, active=scan_config.active)
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
    table = Table("Run", "Started", "Targets", "Findings")
    for run in runs:
        table.add_row(
            run.run_id, run.started_at.isoformat(), str(run.target_count), str(run.finding_count)
        )
    console.print(table)


if __name__ == "__main__":
    app()

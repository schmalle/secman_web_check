"""Rich terminal report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models import ScanRun, public_url


def render_terminal(run: ScanRun, console: Console | None = None) -> None:
    output = console if console is not None else Console()
    output.print(f"[bold]SecMan web-security scan[/bold] {run.run_id} ({run.profile})")
    output.print(f"Profile hash: {run.profile_hash}")
    for target in run.targets:
        output.print(
            f"\n[bold]{public_url(target.target.url)}[/bold] — {target.status.value} "
            f"({len(target.findings)} findings, {len(target.components)} components)"
        )
        if target.coverage.pages_discovered:
            output.print(
                f"Coverage: {target.coverage.pages_scanned} pages scanned, "
                f"{target.coverage.pages_discovered} discovered"
            )
        if target.exposure is not None:
            status = (
                "-" if target.exposure.http_status is None else str(target.exposure.http_status)
            )
            body_length = (
                "-"
                if target.exposure.body_length is None
                else f"{target.exposure.body_length} bytes"
            )
            output.print(
                f"Exposure: {target.exposure.reachability.value} · HTTP {status} · "
                f"{target.exposure.redirect_count} redirects · body {body_length}"
            )
        for error in target.errors:
            output.print(f"[yellow]Incomplete:[/yellow] {error}")
        table = Table(show_header=True)
        table.add_column("Severity")
        table.add_column("Rule")
        table.add_column("Finding")
        table.add_column("Evidence")
        table.add_column("Attribution / validation")
        for finding in target.findings:
            table.add_row(
                finding.severity.value,
                finding.rule_id,
                finding.title,
                finding.evidence,
                f"{finding.engine} / {finding.model or '-'} / {finding.validation_status}",
            )
        output.print(table)
        if target.coverage.executions:
            counts: dict[str, int] = {}
            for item in target.coverage.executions:
                counts[item.state] = counts.get(item.state, 0) + 1
            output.print(
                "Check execution states: "
                + ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
            )
        if target.api_operations:
            api = Table("Method", "API path", "Source", "Parameters", "Execution")
            for operation in target.api_operations:
                api.add_row(
                    operation.method,
                    operation.path,
                    operation.source,
                    ", ".join(operation.parameters),
                    "executed" if operation.executed else "inventory only",
                )
            output.print(api)
        for stage in target.analysis_stages:
            output.print(
                f"Analysis {stage.name}: {stage.state}; model={stage.model}; "
                f"prompt={stage.prompt_hash}; policy={stage.policy_version}"
            )
        if target.components:
            components = Table(show_header=True)
            components.add_column("Category")
            components.add_column("Component")
            components.add_column("Version")
            components.add_column("Evidence")
            for component in target.components:
                components.add_row(
                    component.category.value,
                    component.name,
                    component.version or "unknown",
                    component.evidence,
                )
            output.print(components)
        if target.javascript_assets:
            scripts = Table(show_header=True)
            scripts.add_column("JavaScript URL")
            scripts.add_column("SHA-256")
            scripts.add_column("Bytes", justify="right")
            scripts.add_column("HTTP")
            for asset in target.javascript_assets:
                scripts.add_row(
                    public_url(asset.url),
                    asset.sha256,
                    str(asset.size_bytes),
                    str(asset.status_code),
                )
            output.print(scripts)

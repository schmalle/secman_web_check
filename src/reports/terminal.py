"""Rich terminal report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models import ScanRun


def render_terminal(run: ScanRun, console: Console | None = None) -> None:
    output = console if console is not None else Console()
    output.print(f"[bold]SecMan web-security scan[/bold] {run.run_id}")
    for target in run.targets:
        output.print(
            f"\n[bold]{target.target.url}[/bold] — {target.status.value} "
            f"({len(target.findings)} findings, {len(target.components)} components)"
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
        for finding in target.findings:
            table.add_row(
                finding.severity.value,
                finding.rule_id,
                finding.title,
                finding.evidence,
            )
        output.print(table)
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

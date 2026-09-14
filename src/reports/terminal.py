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
            f"({len(target.findings)} findings)"
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

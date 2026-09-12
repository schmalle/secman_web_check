"""Self-contained escaped HTML report without scripts or remote content."""

from __future__ import annotations

from html import escape
from pathlib import Path

from ..models import ScanRun
from .common import atomic_write


def write_html(run: ScanRun, path: Path) -> Path:
    sections: list[str] = []
    for target in run.targets:
        rows = "".join(
            "<tr>"
            f"<td>{escape(finding.severity.value)}</td>"
            f"<td>{escape(finding.rule_id)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.evidence)}</td>"
            f"<td>{escape(finding.recommendation)}</td>"
            "</tr>"
            for finding in target.findings
        )
        errors = "".join(f"<li>{escape(error)}</li>" for error in target.errors)
        sections.append(
            f"<section><h2>{escape(target.target.url)}</h2>"
            f"<p>Status: <strong>{escape(target.status.value)}</strong></p>"
            f"<ul>{errors}</ul>"
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th>"
            f"<th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{rows}</tbody></table>"
            "</section>"
        )
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        f"<title>SecMan web check {escape(run.run_id)}</title><style>"
        "body{font:16px system-ui;margin:2rem;color:#17202a}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccd1d1;padding:.5rem;text-align:left;vertical-align:top}"
        "th{background:#eef2f3}section{margin-block:2rem;overflow:auto}</style></head><body>"
        f"<h1>SecMan web-security scan</h1><p>Run {escape(run.run_id)}</p>"
        + "".join(sections)
        + "</body></html>\n"
    )
    return atomic_write(path, document)

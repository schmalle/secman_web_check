"""Self-contained escaped HTML report without scripts or remote content."""

from __future__ import annotations

from html import escape
from pathlib import Path

from ..models import ScanRun, public_url
from .common import atomic_write


def write_html(run: ScanRun, path: Path) -> Path:
    sections: list[str] = []
    for target in run.targets:
        finding_rows = "".join(
            "<tr>"
            f"<td>{escape(finding.severity.value)}</td>"
            f"<td>{escape(finding.rule_id)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.evidence)}</td>"
            f"<td>{escape(finding.recommendation)}</td>"
            f"<td>{escape(finding.engine)}; {escape(finding.model or '')}; "
            f"{escape(finding.validation_status)}</td>"
            "</tr>"
            for finding in target.findings
        )
        component_rows = "".join(
            "<tr>"
            f"<td>{escape(component.category.value)}</td>"
            f"<td>{escape(component.name)}</td>"
            f"<td>{escape(component.version or 'unknown')}</td>"
            f"<td>{escape(component.evidence)}</td>"
            "</tr>"
            for component in target.components
        )
        javascript_rows = "".join(
            "<tr>"
            f"<td>{escape(public_url(asset.url))}</td>"
            f"<td><code>{escape(asset.sha256)}</code></td>"
            f"<td>{asset.size_bytes}</td>"
            f"<td>{asset.status_code}</td>"
            "</tr>"
            for asset in target.javascript_assets
        )
        errors = "".join(f"<li>{escape(error)}</li>" for error in target.errors)
        pages = "".join(f"<li>{escape(url)}</li>" for url in target.coverage.pages)
        executions = "".join(
            f"<li>{escape(item.check_id)}: {escape(item.state)} ({escape(item.reason)})</li>"
            for item in target.coverage.executions
        )
        api_rows = "".join(
            f"<tr><td>{escape(item.method)}</td><td>{escape(item.path)}</td>"
            f"<td>{escape(item.source)}</td><td>{escape(', '.join(item.parameters))}</td>"
            f"<td>{'executed' if item.executed else 'inventory only'}</td></tr>"
            for item in target.api_operations
        )
        stages = "".join(
            f"<li>{escape(item.name)}: {escape(item.state)}; "
            f"{escape(item.model or '')}; prompt {escape(item.prompt_hash or '')}; "
            f"policy {escape(item.policy_version or '')}</li>"
            for item in target.analysis_stages
        )
        exposure = "Not observed"
        if target.exposure is not None:
            http_status = (
                "-" if target.exposure.http_status is None else str(target.exposure.http_status)
            )
            body_length = (
                "-"
                if target.exposure.body_length is None
                else f"{target.exposure.body_length} bytes"
            )
            exposure = (
                f"{escape(target.exposure.reachability.value)}; HTTP {http_status}; "
                f"{target.exposure.redirect_count} redirects; body {body_length}"
            )
        sections.append(
            f"<section><h2>{escape(public_url(target.target.url))}</h2>"
            f"<p>Status: <strong>{escape(target.status.value)}</strong></p>"
            f"<p>Coverage: {target.coverage.pages_scanned} pages scanned; "
            f"{target.coverage.pages_discovered} discovered</p>"
            f"<details><summary>Scanned pages</summary><ul>{pages}</ul></details>"
            f"<details><summary>Check executions</summary><ul>{executions}</ul></details>"
            f"<details><summary>Analysis stages</summary><ul>{stages}</ul></details>"
            "<h3>API inventory</h3><table><thead><tr><th>Method</th><th>Path</th>"
            "<th>Source</th><th>Parameter names/types</th><th>Execution</th></tr></thead>"
            f"<tbody>{api_rows}</tbody></table>"
            f"<p>External exposure: <strong>{exposure}</strong></p>"
            f"<ul>{errors}</ul>"
            "<h3>Software components</h3>"
            "<table><thead><tr><th>Category</th><th>Component</th><th>Version</th>"
            f"<th>Evidence</th></tr></thead><tbody>{component_rows}</tbody></table>"
            "<h3>JavaScript assets</h3>"
            "<table><thead><tr><th>URL</th><th>SHA-256</th><th>Bytes</th><th>HTTP</th>"
            f"</tr></thead><tbody>{javascript_rows}</tbody></table>"
            "<h3>Security findings</h3>"
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th>"
            f"<th>Evidence</th><th>Recommendation</th><th>Attribution / validation</th></tr></thead><tbody>{finding_rows}</tbody></table>"
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
        f"<h1>SecMan web-security scan</h1><p>Run {escape(run.run_id)}; "
        f"profile {escape(run.profile)}; hash {escape(run.profile_hash)}</p>"
        f"<details><summary>Coverage manifest</summary><pre>{escape(run.manifest_json)}</pre></details>"
        + "".join(sections)
        + "</body></html>\n"
    )
    return atomic_write(path, document)

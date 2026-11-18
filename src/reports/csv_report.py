"""CSV report: one physical line per finding."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ..models import ScanRun, public_url
from .common import atomic_write, browser_http_label, flag_label, redirect_label

_COLUMNS = (
    "target",
    "aws_account_number",
    "target_status",
    "rule_id",
    "severity",
    "confidence",
    "title",
    "description",
    "recommendation",
    "evidence",
    "url",
    "engine",
    "validation_status",
    "created_at",
    "redirect_followed",
    "browser_navigation_observed",
    "browser_navigation_reason",
    "browser_navigation_hostname",
    "browser_http",
    "browser_navigation_hops",
)


def _cell(value: object) -> str:
    text = " ".join(str("" if value is None else value).split())
    # Keep spreadsheet applications from evaluating scanned content as a formula.
    return "'" + text if text[:1] in {"=", "+", "-", "@"} else text


def write_csv(run: ScanRun, path: Path) -> Path:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for target in run.targets:
        navigation_diagnostic = target.browser_navigation_diagnostic
        for finding in target.findings:
            writer.writerow(
                _cell(value)
                for value in (
                    public_url(target.target.url),
                    target.target.aws_account_number,
                    target.status.value,
                    finding.rule_id,
                    finding.severity.value,
                    finding.confidence,
                    finding.title,
                    finding.description,
                    finding.recommendation,
                    finding.evidence,
                    finding.url,
                    finding.engine,
                    finding.validation_status,
                    finding.created_at.isoformat(),
                    redirect_label(target.exposure),
                    flag_label(target.browser_navigation_observed),
                    navigation_diagnostic.reason if navigation_diagnostic else None,
                    navigation_diagnostic.hostname if navigation_diagnostic else None,
                    browser_http_label(target.browser_http),
                    " → ".join(target.browser_navigation_hops),
                )
            )
    return atomic_write(path, output.getvalue())

"""CSV report: one physical line per finding."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ..models import ScanRun, public_url
from .common import atomic_write

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
                )
            )
    return atomic_write(path, output.getvalue())

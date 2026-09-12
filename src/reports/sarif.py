"""SARIF 2.1.0 report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import ScanRun, Severity
from .common import atomic_write

_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def write_sarif(run: ScanRun, path: Path) -> Path:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for target in run.targets:
        for finding in target.findings:
            rules.setdefault(
                finding.rule_id,
                {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.description or finding.title},
                    "help": {"text": finding.recommendation or finding.description},
                    "properties": {"severity": finding.severity.value},
                },
            )
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": _LEVEL[finding.severity],
                    "message": {"text": f"{finding.title}: {finding.evidence}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}],
                    "partialFingerprints": {"externalId": finding.external_id},
                }
            )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secman-web-check",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"runId": run.run_id},
            }
        ],
    }
    return atomic_write(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")

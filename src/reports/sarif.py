"""SARIF 2.1.0 report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import ScanRun, Severity, public_url
from .common import atomic_write
from .json_report import run_document

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
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": public_url(finding.url)}}}
                    ],
                    "properties": {
                        "engine": finding.engine,
                        "model": finding.model,
                        "validationStatus": finding.validation_status,
                        "evidenceIds": list(finding.evidence_ids),
                        "promptHash": finding.prompt_hash,
                        "policyVersion": finding.policy_version,
                    },
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
                        "version": "0.3.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "runId": run.run_id,
                    "profile": run.profile,
                    "profileHash": run.profile_hash,
                    "coverageManifest": run_document(run)["coverageManifest"],
                    "targets": [
                        {key: value for key, value in item.items() if key != "findings"}
                        for item in run_document(run)["targets"]
                    ],
                },
            }
        ],
    }
    return atomic_write(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")

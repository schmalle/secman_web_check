"""Versioned JSON report."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import Finding, ScanRun, TargetResult
from .common import atomic_write


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _finding_document(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "externalId": finding.external_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "title": finding.title,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "evidence": finding.evidence,
        "url": finding.url,
        "engine": finding.engine,
        "model": finding.model,
        "createdAt": _timestamp(finding.created_at),
    }


def _target_document(target: TargetResult) -> dict[str, Any]:
    return {
        "url": target.target.url,
        "awsAccountNumber": target.target.aws_account_number,
        "status": target.status.value,
        "complete": target.complete,
        "errors": list(target.errors),
        "startedAt": _timestamp(target.started_at),
        "completedAt": _timestamp(target.completed_at),
        "findings": [_finding_document(finding) for finding in target.findings],
    }


def run_document(run: ScanRun) -> dict[str, Any]:
    return {
        "schemaVersion": "1.0",
        "runId": run.run_id,
        "startedAt": _timestamp(run.started_at),
        "completedAt": _timestamp(run.completed_at),
        "targets": [_target_document(target) for target in run.targets],
    }


def write_json(run: ScanRun, path: Path) -> Path:
    return atomic_write(path, json.dumps(run_document(run), indent=2, ensure_ascii=False) + "\n")

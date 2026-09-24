"""Versioned JSON report."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import (
    DetectedComponent,
    ExposureObservation,
    Finding,
    JavaScriptAsset,
    ScanRun,
    TargetResult,
)
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


def _component_document(component: DetectedComponent) -> dict[str, Any]:
    return {
        "componentKey": component.component_key,
        "category": component.category.value,
        "name": component.name,
        "version": component.version,
        "confidence": component.confidence,
        "evidenceType": component.evidence_type,
        "evidence": component.evidence,
        "sourceUrl": component.source_url,
    }


def _exposure_document(exposure: ExposureObservation | None) -> dict[str, Any] | None:
    if exposure is None:
        return None
    return {
        "configuredUrl": exposure.configured_url,
        "effectiveUrl": exposure.effective_url,
        "reachability": exposure.reachability.value,
        "httpStatus": exposure.http_status,
        "redirectCount": exposure.redirect_count,
        "bodyLength": exposure.body_length,
        "vantagePoint": exposure.vantage_point,
    }


def _javascript_document(asset: JavaScriptAsset) -> dict[str, Any]:
    return {
        "url": asset.url,
        "sha256": asset.sha256,
        "sizeBytes": asset.size_bytes,
        "statusCode": asset.status_code,
        "truncated": asset.truncated,
    }


def _target_document(target: TargetResult) -> dict[str, Any]:
    return {
        "url": target.target.url,
        "awsAccountNumber": target.target.aws_account_number,
        "status": target.status.value,
        "complete": target.complete,
        "inventoryComplete": target.inventory_complete,
        "exposure": _exposure_document(target.exposure),
        "components": [_component_document(component) for component in target.components],
        "javascriptAssets": [_javascript_document(asset) for asset in target.javascript_assets],
        "errors": list(target.errors),
        "startedAt": _timestamp(target.started_at),
        "completedAt": _timestamp(target.completed_at),
        "findings": [_finding_document(finding) for finding in target.findings],
    }


def run_document(run: ScanRun) -> dict[str, Any]:
    return {
        "schemaVersion": "1.2",
        "runId": run.run_id,
        "startedAt": _timestamp(run.started_at),
        "completedAt": _timestamp(run.completed_at),
        "targets": [_target_document(target) for target in run.targets],
    }


def write_json(run: ScanRun, path: Path) -> Path:
    return atomic_write(path, json.dumps(run_document(run), indent=2, ensure_ascii=False) + "\n")

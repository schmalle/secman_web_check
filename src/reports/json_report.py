"""Versioned JSON report."""

from __future__ import annotations

import json
from dataclasses import asdict
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
    public_url,
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
        "evidenceIds": list(finding.evidence_ids),
        "validationStatus": finding.validation_status,
        "promptHash": finding.prompt_hash,
        "policyVersion": finding.policy_version,
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
        "url": public_url(asset.url),
        "sha256": asset.sha256,
        "sizeBytes": asset.size_bytes,
        "statusCode": asset.status_code,
        "truncated": asset.truncated,
    }


def _target_document(target: TargetResult) -> dict[str, Any]:
    return {
        "url": public_url(target.target.url),
        "awsAccountNumber": target.target.aws_account_number,
        "secmanSubjectId": target.target.secman_subject_id,
        "secmanAssetId": target.target.secman_asset_id,
        "status": target.status.value,
        "complete": target.complete,
        "inventoryComplete": target.inventory_complete,
        "coverage": {
            "pagesScanned": target.coverage.pages_scanned,
            "pagesDiscovered": target.coverage.pages_discovered,
            "pages": list(target.coverage.pages),
            "crawlRequests": target.coverage.crawl_requests,
            "httpRequests": target.coverage.http_requests,
            "crawlComplete": target.coverage.crawl_complete,
            "agentActions": target.coverage.agent_actions,
            "agentComplete": target.coverage.agent_complete,
            "queryInput": target.coverage.query_input,
            "executions": [
                {**asdict(item), "evidence_ids": list(item.evidence_ids)}
                for item in target.coverage.executions
            ],
        },
        "exposure": _exposure_document(target.exposure),
        "components": [_component_document(component) for component in target.components],
        "javascriptAssets": [_javascript_document(asset) for asset in target.javascript_assets],
        "errors": list(target.errors),
        "evidenceRecords": [asdict(item) for item in target.evidence_records],
        "apiOperations": [
            {
                **asdict(item),
                "parameters": list(item.parameters),
                "request_content_types": list(item.request_content_types),
                "response_content_types": list(item.response_content_types),
            }
            for item in target.api_operations
        ],
        "analysisStages": [
            {
                **asdict(item),
                "started_at": _timestamp(item.started_at),
                "completed_at": _timestamp(item.completed_at),
            }
            for item in target.analysis_stages
        ],
        "startedAt": _timestamp(target.started_at),
        "completedAt": _timestamp(target.completed_at),
        "findings": [_finding_document(finding) for finding in target.findings],
    }


def run_document(run: ScanRun) -> dict[str, Any]:
    return {
        "schemaVersion": "1.3",
        "runId": run.run_id,
        "profile": run.profile,
        "profileHash": run.profile_hash,
        "trafficMetrics": json.loads(run.metrics_json),
        "coverageManifest": json.loads(run.manifest_json),
        "startedAt": _timestamp(run.started_at),
        "completedAt": _timestamp(run.completed_at),
        "targets": [_target_document(target) for target in run.targets],
    }


def write_json(run: ScanRun, path: Path) -> Path:
    return atomic_write(path, json.dumps(run_document(run), indent=2, ensure_ascii=False) + "\n")

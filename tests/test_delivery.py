from dataclasses import replace
from datetime import UTC, datetime

from secman_web_check.delivery import templates
from secman_web_check.models import (
    ExposureObservation,
    Reachability,
    ScanRun,
    TargetResult,
    TargetStatus,
)
from secman_web_check.reports.json_report import run_document
from secman_web_check.targets import normalize_target


def test_authenticated_response_is_reachable_but_never_resolution_evidence():
    now = datetime.now(UTC)
    target = TargetResult(
        normalize_target("https://example.com/"),
        TargetStatus.SUCCESS,
        started_at=now,
        completed_at=now,
        exposure=ExposureObservation(
            "https://example.com/",
            "https://example.com/",
            Reachability.AUTHENTICATED,
            403,
            0,
            body_length=42,
        ),
    )
    run = ScanRun(run_id="test-run", targets=(target,), started_at=now, completed_at=now)
    body = templates(run_document(run), 1, "security")[0]["body"]
    assert body["inventory"]["exposure"]["reachability"] == "REACHABLE"
    assert "bodyLength" not in body["inventory"]["exposure"]
    assert body["completeCoverage"] is False
    assert "authenticationRequired" in body["metadataJson"]


def test_report_retains_exact_subject_and_asset_for_later_upload():
    now = datetime.now(UTC)
    target = replace(
        normalize_target("https://example.com/"), secman_subject_id=2, secman_asset_id=3
    )
    run = ScanRun(
        run_id="test-run",
        targets=(TargetResult(target, TargetStatus.SUCCESS, started_at=now, completed_at=now),),
        started_at=now,
        completed_at=now,
    )
    item = templates(run_document(run), 1, "visual")[0]
    assert item["subjectId"] == 2 and item["assetId"] == 3
    assert item["body"]["completeCoverage"] is False


def test_resolution_requires_live_scan_and_explicit_matching_approval(monkeypatch):
    import hashlib
    import json

    document = {
        "schemaVersion": "1.3",
        "profile": "security:passive",
        "coverageManifest": {"version": 1},
        "targets": [
            {
                "url": "https://example.com/",
                "status": "SUCCESS",
                "complete": True,
                "inventoryComplete": True,
                "findings": [],
                "startedAt": "2026-10-21T00:00:00Z",
                "completedAt": "2026-10-21T00:01:00Z",
                "exposure": {
                    "httpStatus": 200,
                    "redirectCount": 0,
                    "configuredUrl": "https://example.com/",
                    "effectiveUrl": "https://example.com/",
                },
            }
        ],
    }
    monkeypatch.delenv("SECMAN_BASELINE_PROFILE_SHA256", raising=False)
    assert not templates(document, 1, "security", allow_resolution=True)[0]["body"][
        "completeCoverage"
    ]
    approved = hashlib.sha256(
        json.dumps({"version": 1}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    monkeypatch.setenv("SECMAN_BASELINE_PROFILE_SHA256", approved)
    document["profileHash"] = approved
    assert templates(document, 1, "security", allow_resolution=True)[0]["body"]["completeCoverage"]
    assert not templates(document, 1, "security")[0]["body"]["completeCoverage"]
    document["coverageManifest"]["changed"] = True
    assert not templates(document, 1, "security", allow_resolution=True)[0]["body"][
        "completeCoverage"
    ]


def test_imported_asset_id_cannot_override_target_identity():
    from unittest.mock import Mock

    import pytest

    from secman_web_check.delivery import prepare
    from secman_web_check.integration_outbox import DeliveryError
    from secman_web_check.secman import IntegrationSubject

    client = Mock()
    client.list_subjects.return_value = [
        IntegrationSubject(2, 1, 3, "other.example.com", "https://other.example.com/")
    ]
    with pytest.raises(DeliveryError, match="bound_target_mismatch"):
        prepare(client, {"scannerId": 1, "assetId": 3, "url": "https://example.com/", "body": {}})

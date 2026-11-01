"""Persist web snapshots before discovery/upload; replay without rescanning targets."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .integration_outbox import DeliveryError, Outbox, canonical
from .secman import IntegrationClient, IntegrationSubject, match_subject, validate_base_url


def queue_path() -> Path:
    return Path(
        os.environ.get("SECMAN_WEB_CHECK_OUTBOX", "~/.local/state/secman-web-check/delivery")
    ).expanduser()


def destination() -> str:
    return validate_base_url(os.environ.get("SECMAN_URL", ""))


def templates(
    document: dict[str, Any], scanner: int, mode: str, *, allow_resolution: bool = False
) -> list[dict[str, Any]]:
    if document.get("schemaVersion") != "1.3" or scanner <= 0:
        raise ValueError("Expected web report schema 1.3 and a positive scanner ID")
    if str(document.get("profile", "")).startswith("combined:"):
        raise ValueError(
            "Upload each mode's report separately; combined reports are for local review"
        )
    approved_hash = os.environ.get("SECMAN_BASELINE_PROFILE_SHA256", "")
    manifest_hash = hashlib.sha256(
        json.dumps(
            document.get("coverageManifest", {}), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    result = []
    for target in document["targets"]:
        exposure = target.get("exposure")
        eligible = (
            allow_resolution
            and mode == "security"
            and document["profile"] == "security:passive"
            and document.get("coverageManifest", {}).get("version") == 1
            and len(approved_hash) == 64
            and document.get("profileHash") == approved_hash == manifest_hash
            and not target.get("coverage", {}).get("queryInput")
            and exposure is not None
            and exposure.get("httpStatus") == 200
            and exposure.get("redirectCount") == 0
            and exposure.get("effectiveUrl") == exposure.get("configuredUrl")
        )
        metadata = {
            "scannerVersion": "0.3.0",
            "scanMode": mode,
            "profile": document["profile"],
            "profileHash": document.get("profileHash"),
            "reportSchema": "1.3",
            "coverageReason": "APPROVED_BASELINE" if eligible else "NON_RESOLVING_PROFILE",
            "authenticationRequired": bool(
                exposure and exposure.get("reachability") == "AUTHENTICATED"
            ),
            "discoveryCounts": {
                key: len(target.get(key, []))
                for key in (
                    "javascriptAssets",
                    "apiOperations",
                    "evidenceRecords",
                    "analysisStages",
                )
            },
        }
        fields = (
            "externalId",
            "severity",
            "title",
            "description",
            "recommendation",
            "evidence",
            "url",
            "confidence",
            "engine",
            "model",
        )
        findings = [{key: f.get(key) for key in fields} for f in target["findings"]]
        if target["status"] == "FAILED":
            findings = []
        if len(findings) > 500 or len(target.get("components", [])) > 500:
            raise ValueError("Snapshot exceeds the 500-record limit; retain the local report")
        if len({f["externalId"] for f in findings}) != len(findings):
            raise ValueError("Duplicate finding identities")
        body = {
            "scannerId": scanner,
            "status": target["status"],
            "completeCoverage": bool(eligible and target["complete"] is True),
            "startedAt": target["startedAt"],
            "completedAt": target["completedAt"],
            "metadataJson": canonical(metadata),
            "findings": sorted(findings, key=lambda f: f["externalId"]),
        }
        if exposure is not None or target.get("components"):
            wire_exposure = (
                None
                if exposure is None
                else {
                    key: exposure.get(key)
                    for key in (
                        "configuredUrl",
                        "effectiveUrl",
                        "reachability",
                        "httpStatus",
                        "redirectCount",
                        "vantagePoint",
                    )
                }
            )
            if wire_exposure and wire_exposure["reachability"] == "AUTHENTICATED":
                wire_exposure["reachability"] = "REACHABLE"
            body["inventory"] = {
                "completeCoverage": bool(eligible and target["inventoryComplete"] is True),
                "exposure": wire_exposure,
                "components": target.get("components", []),
            }
        if len(canonical(body).encode()) > 5 * 1024 * 1024:
            raise ValueError("Snapshot exceeds evidence budget; retain the local report")
        result.append(
            {
                "scannerId": scanner,
                "body": body,
                "url": target["url"],
                "awsAccountNumber": target.get("awsAccountNumber"),
                "subjectId": target.get("secmanSubjectId"),
                "assetId": target.get("secmanAssetId"),
            }
        )
    return result


def prepare(client: IntegrationClient, item: dict[str, Any]) -> dict[str, Any]:
    subjects = client.list_subjects(item["scannerId"])
    subject: IntegrationSubject | None
    if item.get("assetId") is not None:
        # Another scan mode may have a different subject for the exact same asset.
        matches = [s for s in subjects if s.asset_id == item["assetId"]]
        if len(matches) != 1:
            raise DeliveryError("bound_asset_not_authorized")
        subject = matches[0]
        if (
            match_subject([subject], item["url"], aws_account_number=item.get("awsAccountNumber"))
            is None
        ):
            raise DeliveryError("bound_target_mismatch")
        if (
            item.get("subjectId")
            and any(s.id == item["subjectId"] for s in subjects)
            and subject.id != item["subjectId"]
        ):
            raise DeliveryError("subject_binding_changed")
    else:
        subject = match_subject(
            subjects, item["url"], aws_account_number=item.get("awsAccountNumber")
        )
        if subject is None:
            raise DeliveryError("subject_not_found")
    body = dict(item["body"], subjectId=subject.id)
    body["runKey"] = "secman-web-check-v1:" + hashlib.sha256(canonical(body).encode()).hexdigest()
    return body


def enqueue(
    document: dict[str, Any], scanner: int, mode: str, *, allow_resolution: bool = False
) -> list[str]:
    url = destination()
    queue = Outbox(queue_path())
    try:
        return [
            queue.enqueue(url, item)
            for item in templates(document, scanner, mode, allow_resolution=allow_resolution)
        ]
    finally:
        queue.close()


def synchronize(queue: Outbox, factory: Any, *, resume: bool = False) -> list[dict[str, Any]]:
    from contextlib import ExitStack

    with ExitStack() as stack:
        client: IntegrationClient | None = None

        def active() -> IntegrationClient:
            nonlocal client
            if client is None:
                client = stack.enter_context(factory())
            return client

        return queue.retry(
            destination(),
            lambda item: prepare(active(), item),
            lambda body: active().submit_run(body),
            resume=resume,
        )

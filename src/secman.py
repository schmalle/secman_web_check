"""Version-1 SecMan integration-result client for web-security scans."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Self
from urllib.parse import urlsplit, urlunsplit

import httpx

from .models import Finding, TargetResult

_TIMEOUT_SECONDS = 30.0


class SecmanIntegrationError(RuntimeError):
    """Raised when the SecMan integration contract cannot be satisfied."""


class AmbiguousSubject(SecmanIntegrationError):
    """Raised when a target does not map to exactly one authorized subject."""


@dataclass(frozen=True, slots=True)
class IntegrationSubject:
    id: int
    scanner_id: int
    asset_id: int
    name: str
    uri: str | None
    cloud_account_id: str | None = None

    @classmethod
    def from_api(cls, value: Mapping[str, Any]) -> IntegrationSubject:
        try:
            return cls(
                id=int(value["id"]),
                scanner_id=int(value["scannerId"]),
                asset_id=int(value["assetId"]),
                name=str(value["name"]),
                uri=None if value.get("uri") is None else str(value["uri"]),
                cloud_account_id=(
                    None if value.get("cloudAccountId") is None else str(value["cloudAccountId"])
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SecmanIntegrationError(
                "SecMan returned an invalid integration subject"
            ) from error


def validate_base_url(value: str) -> str:
    """Accept only an absolute HTTPS origin without embedded credentials."""
    parts = urlsplit(value.strip())
    if parts.scheme != "https" or not parts.hostname:
        raise SecmanIntegrationError("SecMan URL must be an absolute HTTPS URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise SecmanIntegrationError(
            "SecMan URL must not contain credentials, a query, or a fragment"
        )
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def match_subject(
    subjects: Iterable[IntegrationSubject],
    target_url: str,
    *,
    aws_account_number: str | None = None,
) -> IntegrationSubject | None:
    """Match by AWS account when supplied, then canonical URL or hostname."""
    available = tuple(subjects)
    if aws_account_number is not None:
        available = tuple(
            subject for subject in available if subject.cloud_account_id == aws_account_number
        )
    target = urlsplit(target_url)
    exact = tuple(
        subject
        for subject in available
        if subject.uri and subject.uri.rstrip("/") == target_url.rstrip("/")
    )
    if len(exact) > 1:
        raise AmbiguousSubject("multiple SecMan subjects match the target URI")
    if exact:
        return exact[0]
    hostname = tuple(
        subject for subject in available if subject.name.lower() == (target.hostname or "").lower()
    )
    if len(hostname) > 1:
        raise AmbiguousSubject("multiple SecMan subjects match the target hostname")
    return hostname[0] if hostname else None


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _finding_body(finding: Finding) -> dict[str, Any]:
    return {
        "externalId": finding.external_id,
        "legacyIds": [],
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description or None,
        "recommendation": finding.recommendation or None,
        "evidence": finding.evidence or None,
        "filePath": None,
        "lineRange": None,
        "url": finding.url,
        "confidence": finding.confidence,
        "engine": "secman-web-check",
        "model": None,
        "commitSha": None,
        "issueUrl": None,
        "fixPrUrl": None,
        "attachments": [],
    }


def build_run_body(
    scanner_id: int,
    subject: IntegrationSubject,
    result: TargetResult,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic terminal snapshot using SecMan's version-1 schema."""
    if subject.scanner_id != scanner_id:
        raise SecmanIntegrationError("integration subject belongs to a different scanner")
    findings = (
        []
        if result.status.value == "FAILED"
        else [_finding_body(finding) for finding in result.findings]
    )
    if len(findings) > 500:
        raise SecmanIntegrationError("integration run exceeds the 500-finding limit")
    findings.sort(key=lambda finding: str(finding["externalId"]))
    external_ids = [finding["externalId"] for finding in findings]
    if len(external_ids) != len(set(external_ids)):
        raise SecmanIntegrationError("integration run contains duplicate finding identities")
    body: dict[str, Any] = {
        "scannerId": scanner_id,
        "subjectId": subject.id,
        "status": result.status.value,
        "completeCoverage": result.complete,
        "startedAt": _timestamp(result.started_at),
        "completedAt": _timestamp(result.completed_at),
        "metadataJson": json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")),
        "findings": findings,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    body["runKey"] = "secman-web-check-v1:" + hashlib.sha256(canonical.encode()).hexdigest()
    return body


class IntegrationClient:
    """Authenticated client for subject discovery and atomic run submission."""

    def __init__(self, base_url: str, token: str) -> None:
        if not token:
            raise SecmanIntegrationError("SecMan token must not be empty")
        self._client = httpx.Client(
            base_url=validate_base_url(base_url),
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=False,
        )

    @classmethod
    def login(cls, base_url: str, username: str, password: str) -> IntegrationClient:
        if not username or not password:
            raise SecmanIntegrationError("SecMan credentials must not be empty")
        instance = cls.__new__(cls)
        instance._client = httpx.Client(
            base_url=validate_base_url(base_url),
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=False,
        )
        try:
            response = instance._client.post(
                "/api/auth/login",
                json={"username": username, "password": password},
            )
        except httpx.HTTPError as error:
            instance.close()
            raise SecmanIntegrationError("SecMan login request failed") from error
        if response.status_code not in {200, 204}:
            instance.close()
            raise SecmanIntegrationError(f"SecMan login failed with HTTP {response.status_code}")
        return instance

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def list_subjects(self, scanner_id: int, *, size: int = 100) -> list[IntegrationSubject]:
        if size < 1 or size > 100:
            raise ValueError("subject page size must be between 1 and 100")
        subjects: list[IntegrationSubject] = []
        page = 0
        while True:
            try:
                response = self._client.get(
                    f"/api/integrations/v1/scanners/{scanner_id}/subjects",
                    params={"page": page, "size": size},
                )
            except httpx.HTTPError as error:
                raise SecmanIntegrationError("SecMan subject discovery request failed") from error
            if response.status_code != 200:
                raise SecmanIntegrationError(
                    f"SecMan subject discovery failed with HTTP {response.status_code}"
                )
            try:
                payload = response.json()
                subjects.extend(IntegrationSubject.from_api(row) for row in payload["content"])
                total_pages = int(payload["totalPages"])
            except (KeyError, TypeError, ValueError) as error:
                raise SecmanIntegrationError(
                    "SecMan subject discovery returned an invalid response"
                ) from error
            page += 1
            if page >= total_pages:
                return subjects

    def submit_run(self, body: Mapping[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post("/api/integrations/v1/runs", json=dict(body))
        except httpx.HTTPError as error:
            raise SecmanIntegrationError("SecMan run submission request failed") from error
        if response.status_code not in {200, 201}:
            raise SecmanIntegrationError(
                f"SecMan run submission failed with HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except ValueError as error:
            raise SecmanIntegrationError("SecMan run submission returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise SecmanIntegrationError("SecMan run submission returned an invalid response")
        return payload

"""Import Cloudflare security-audit-skill results and publish them as issues.

The skill (https://github.com/cloudflare/security-audit-skill) audits *source code* and
writes ``findings.json`` validated against its ``report-schema.json``. This module reads
that file locally, normalizes the records, and optionally publishes them to GitHub Issues
and to SecMan. Nothing here runs the skill, executes target code, or contacts a target.

Safety defaults: only ``confirmed`` records are imported, ``rejected`` records are never
published, and attacker payloads and reproduction steps are omitted unless the operator
explicitly asks for them.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

import httpx
import truststore

from .models import Severity
from .secman import IntegrationSubject, SecmanIntegrationError, _timestamp

ENGINE = "cloudflare-security-audit"
ISSUE_LABEL = "security-audit"
MARKER_PREFIX = "secman-web-check:audit:"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 500
_FINGERPRINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
_MARKER = re.compile(r"<!-- " + re.escape(MARKER_PREFIX) + r"([A-Za-z0-9._:/@+-]+) -->")
_REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MENTION = re.compile(r"@(?=[A-Za-z0-9])")
_SEVERITY = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
_CONFIDENCE = {"low": 0.3, "medium": 0.6, "high": 0.9}


class AuditError(ValueError):
    """Raised when audit input or a publishing step cannot be trusted."""


def _clean(value: object, limit: int) -> str:
    """Bound text, drop control characters, and defuse GitHub @mentions."""
    text = _CONTROL.sub("", str(value)).strip()
    text = _MENTION.sub("@\u200b", text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _safe_path(value: object) -> str:
    path = _CONTROL.sub("", str(value)).replace("\\", "/").strip()
    parts = path.split("/")
    if not path or path.startswith("/") or ".." in parts or len(path) > 512:
        raise AuditError("finding references an unsafe or absolute file path")
    return path


def _line_range(locations: Iterable[Mapping[str, Any]]) -> tuple[str, str | None]:
    """Return the first sink (else first evidence) file and a compact line range."""
    first = next(iter(locations), None)
    if first is None:
        raise AuditError("finding has no source location")
    file = _safe_path(first.get("file", ""))
    lines = sorted(
        {
            int(item["line"])
            for item in locations
            if item.get("file") == first.get("file") and isinstance(item.get("line"), int)
            and item["line"] > 0
        }
    )
    if not lines:
        return file, None
    return file, str(lines[0]) if len(lines) == 1 else f"{lines[0]}-{lines[-1]}"


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """A normalized, publishable view of one findings.json record."""

    fingerprint: str
    verdict: str
    severity: Severity
    confidence: float
    title: str
    description: str
    root_cause: str
    remediation: str
    file_path: str
    line_range: str | None
    evidence: tuple[str, ...]
    trace: tuple[str, ...]
    execution: tuple[str, ...] = ()

    @property
    def validated(self) -> bool:
        return self.verdict == "confirmed"

    @property
    def external_id(self) -> str:
        return "CF-AUDIT:" + hashlib.sha256(self.fingerprint.encode()).hexdigest()

    @property
    def location(self) -> str:
        return self.file_path + (f":{self.line_range}" if self.line_range else "")

    @property
    def issue_title(self) -> str:
        prefix = "" if self.validated else "[needs validation] "
        return _clean(f"[{self.severity.value}] {prefix}{self.title}", 240)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "externalId": self.external_id,
            "verdict": self.verdict,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "rootCause": self.root_cause,
            "remediation": self.remediation,
            "filePath": self.file_path,
            "lineRange": self.line_range,
            "evidence": list(self.evidence),
            "trace": list(self.trace),
        }


def _describe(items: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    return tuple(
        _clean(f"`{_safe_path(i.get('file', ''))}:{i.get('line', '?')}` {i.get('description', '')}", 600)
        for i in items
    )


def _parse_record(record: Mapping[str, Any], index: int, *, exploit_detail: bool) -> AuditFinding | None:
    verdict = record.get("verdict")
    if verdict == "rejected":
        return None
    if verdict not in {"confirmed", "needs_validation"}:
        raise AuditError(f"record {index}: unsupported verdict")
    fingerprint = record.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise AuditError(f"record {index}: invalid fingerprint")
    for name in ("title", "description"):
        if not isinstance(record.get(name), str) or not record[name].strip():
            raise AuditError(f"record {index}: missing {name}")
    trace, evidence = record.get("trace"), record.get("evidence")
    if not (isinstance(trace, list) and trace and all(isinstance(i, dict) for i in trace)):
        raise AuditError(f"record {index}: trace must be a non-empty list")
    if not (isinstance(evidence, list) and evidence and all(isinstance(i, dict) for i in evidence)):
        raise AuditError(f"record {index}: evidence must be a non-empty list")
    sinks = [i for i in trace if i.get("kind") == "sink"]
    file_path, lines = _line_range(sinks or evidence)
    execution: tuple[str, ...] = ()
    if verdict == "confirmed":
        try:
            severity = _SEVERITY[record["severity"]["overall_severity"]]
            confidence = _CONFIDENCE[record["confidence"]["score"]]
            root_cause = _clean(record["root_cause"], 4000)
            remediation = _clean(record["remediation"]["strategy"], 4000)
        except (KeyError, TypeError) as error:
            raise AuditError(f"record {index}: incomplete confirmed record") from error
        if exploit_detail and isinstance(record.get("execution"), dict):
            run = record["execution"]
            execution = tuple(
                _clean(item, 1000)
                for item in (
                    *[f"payload: {p}" for p in run.get("payloads", [])],
                    *[f"step: {s}" for s in run.get("instructions", [])],
                    f"observed: {run.get('observed_result', '')}",
                )
            )
    else:
        severity, confidence = Severity.INFO, _CONFIDENCE["low"]
        root_cause = _clean(record.get("claimed_root_cause", ""), 4000)
        blockers = record.get("blockers") or []
        remediation = "Unresolved before triage: " + "; ".join(_clean(b, 500) for b in blockers)
    return AuditFinding(
        fingerprint=fingerprint,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        title=_clean(record["title"], 200),
        description=_clean(record["description"], 6000),
        root_cause=root_cause,
        remediation=remediation,
        file_path=file_path,
        line_range=lines,
        evidence=_describe(evidence)[:10],
        trace=_describe(trace)[:15],
        execution=execution,
    )


def load_audit_findings(
    path: Path,
    *,
    include_needs_validation: bool = False,
    min_severity: Severity = Severity.INFO,
    include_exploit_detail: bool = False,
) -> tuple[AuditFinding, ...]:
    """Read a skill ``findings.json`` file and return deduplicated, publishable findings."""
    if path.stat().st_size > MAX_FILE_BYTES:
        raise AuditError("findings file exceeds the 16 MiB limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AuditError("findings file is unreadable or not valid JSON") from error
    if isinstance(document, dict) and isinstance(document.get("findings"), list):
        document = document["findings"]
    if not isinstance(document, list) or not all(isinstance(i, dict) for i in document):
        raise AuditError("findings file must be a JSON array of finding records")
    if len(document) > MAX_RECORDS:
        raise AuditError(f"findings file exceeds the {MAX_RECORDS}-record limit")
    parsed: dict[str, AuditFinding] = {}
    for index, record in enumerate(document):
        item = _parse_record(record, index, exploit_detail=include_exploit_detail)
        if item is None or (not item.validated and not include_needs_validation):
            continue
        if item.validated and _RANK[item.severity] < _RANK[min_severity]:
            continue
        parsed.setdefault(item.fingerprint, item)
    return tuple(sorted(parsed.values(), key=lambda f: (-_RANK[f.severity], f.fingerprint)))


def render_issue_body(finding: AuditFinding, *, commit_sha: str | None = None) -> str:
    """Markdown issue body with a hidden idempotency marker."""
    lines = [
        f"<!-- {MARKER_PREFIX}{finding.fingerprint} -->",
        f"**Severity:** {finding.severity.value}  ",
        f"**Verdict:** {finding.verdict}  ",
        f"**Location:** `{finding.location}`"
        + (f" @ `{_clean(commit_sha, 64)}`" if commit_sha else ""),
        "",
        "## Description",
        finding.description,
        "",
        "## Root cause",
        finding.root_cause or "_Not provided._",
        "",
        "## Evidence",
        *[f"- {item}" for item in finding.evidence],
        "",
        "## Trace",
        *[f"{n}. {item}" for n, item in enumerate(finding.trace, 1)],
        "",
        "## Remediation" if finding.validated else "## Open questions",
        finding.remediation or "_Not provided._",
    ]
    if finding.execution:
        lines += ["", "## Reproduction (operator opted in)", *[f"- {i}" for i in finding.execution]]
    lines += ["", "---", "_Imported from Cloudflare security-audit-skill by secman-web-check._"]
    return "\n".join(lines)


def _ssl_context() -> ssl.SSLContext:
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


class GithubIssueClient:
    """Minimal GitHub Issues client with idempotent, marker-based de-duplication."""

    def __init__(self, repo: str, token: str, *, base_url: str = "https://api.github.com") -> None:
        if not _REPO.fullmatch(repo):
            raise AuditError("GitHub repository must be written owner/name")
        if not token:
            raise AuditError("GITHUB_TOKEN (or GH_TOKEN) is required to publish issues")
        self.repo = repo
        self._client = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            verify=_ssl_context(),
            timeout=30.0,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as error:
            raise AuditError("GitHub request failed") from error
        if response.status_code not in {200, 201}:
            raise AuditError(f"GitHub request failed with HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as error:
            raise AuditError("GitHub returned invalid JSON") from error

    def is_private(self) -> bool:
        payload = self._request("GET", f"/repos/{self.repo}")
        return bool(isinstance(payload, dict) and payload.get("private") is True)

    def existing(self, *, max_pages: int = 10) -> dict[str, str]:
        """Map fingerprint -> issue URL for issues already created by this importer."""
        found: dict[str, str] = {}
        for page in range(1, max_pages + 1):
            rows = self._request(
                "GET",
                f"/repos/{self.repo}/issues",
                params={"state": "all", "labels": ISSUE_LABEL, "per_page": 100, "page": page},
            )
            if not isinstance(rows, list):
                raise AuditError("GitHub returned an invalid issue list")
            for row in rows:
                if "pull_request" in row:
                    continue
                match = _MARKER.search(str(row.get("body") or ""))
                if match:
                    found[match.group(1)] = str(row.get("html_url", ""))
            if len(rows) < 100:
                break
        return found

    def create(self, finding: AuditFinding, *, commit_sha: str | None = None) -> str:
        payload = self._request(
            "POST",
            f"/repos/{self.repo}/issues",
            json={
                "title": finding.issue_title,
                "body": render_issue_body(finding, commit_sha=commit_sha),
                "labels": [ISSUE_LABEL, f"severity:{finding.severity.value.lower()}"],
            },
        )
        url = str(payload.get("html_url", "")) if isinstance(payload, dict) else ""
        if not url.startswith("https://github.com/"):
            raise AuditError("GitHub returned an unexpected issue URL")
        return url


def publish_github_issues(
    client: GithubIssueClient,
    findings: Iterable[AuditFinding],
    *,
    commit_sha: str | None = None,
    allow_public: bool = False,
    max_issues: int = 25,
) -> dict[str, str]:
    """Create one issue per new finding; returns fingerprint -> issue URL (new and existing)."""
    if not allow_public and not client.is_private():
        raise AuditError(
            "refusing to publish vulnerability details to a public repository; "
            "pass --allow-public-repo to override"
        )
    urls = client.existing()
    created = 0
    for finding in findings:
        if finding.fingerprint in urls:
            continue
        if created >= max_issues:
            raise AuditError(f"stopped after {max_issues} new issues (--max-issues); rerun to continue")
        urls[finding.fingerprint] = client.create(finding, commit_sha=commit_sha)
        created += 1
    return urls


def build_audit_run_body(
    scanner_id: int,
    subject: IntegrationSubject,
    findings: Iterable[AuditFinding],
    *,
    target_url: str,
    commit_sha: str | None = None,
    issue_urls: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a non-resolving REST v1 snapshot; ``completeCoverage`` is always false."""
    if subject.scanner_id != scanner_id:
        raise SecmanIntegrationError("integration subject belongs to a different scanner")
    stamp = _timestamp((now or datetime.now(UTC)).astimezone(UTC))
    bodies: list[dict[str, Any]] = [
        {
            "externalId": f.external_id,
            "legacyIds": [],
            "severity": f.severity.value,
            "title": f.issue_title if not f.validated else f.title,
            "description": _clean(f.description + "\n\nRoot cause: " + f.root_cause, 8000),
            "recommendation": f.remediation or None,
            "evidence": "\n".join(f.evidence)[:4000] or None,
            "filePath": f.file_path,
            "lineRange": f.line_range,
            "url": target_url,
            "confidence": f.confidence,
            "engine": ENGINE,
            "model": None,
            "commitSha": commit_sha,
            "issueUrl": (issue_urls or {}).get(f.fingerprint),
            "fixPrUrl": None,
            "attachments": [],
        }
        for f in findings
    ]
    bodies.sort(key=lambda item: str(item["externalId"]))
    if len(bodies) > 500:
        raise SecmanIntegrationError("integration run exceeds the 500-finding limit")
    body: dict[str, Any] = {
        "scannerId": scanner_id,
        "subjectId": subject.id,
        "status": "SUCCESS",
        "completeCoverage": False,
        "startedAt": stamp,
        "completedAt": stamp,
        "metadataJson": json.dumps(
            {"source": ENGINE, "kind": "source-code-audit"}, sort_keys=True, separators=(",", ":")
        ),
        "findings": bodies,
    }
    # The timestamp is excluded so a retry of the same findings keeps one run key.
    stable = {k: v for k, v in body.items() if k not in {"startedAt", "completedAt"}}
    canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    body["runKey"] = "secman-web-check-audit-v1:" + hashlib.sha256(canonical.encode()).hexdigest()
    return body

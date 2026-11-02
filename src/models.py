"""Immutable normalized values shared by scanner stages and output adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

from .targets import NormalizedTarget


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TargetStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ComponentCategory(StrEnum):
    JAVASCRIPT_LIBRARY = "JAVASCRIPT_LIBRARY"
    CSS_LIBRARY = "CSS_LIBRARY"
    WEB_SERVER = "WEB_SERVER"


class Reachability(StrEnum):
    REACHABLE = "REACHABLE"
    AUTHENTICATED = "AUTHENTICATED"
    UNKNOWN = "UNKNOWN"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def public_url(value: str) -> str:
    """Retain a location without potentially sensitive query or fragment values."""
    parts = urlsplit(value)
    host = parts.hostname or ""
    authority = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        authority += f":{parts.port}"
    return urlunsplit((parts.scheme, authority, parts.path or "/", "", ""))


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    external_id: str
    severity: Severity
    confidence: float
    title: str
    description: str
    recommendation: str
    evidence: str
    url: str
    engine: str = "secman-web-check"
    model: str | None = None
    created_at: datetime = field(default_factory=_now)
    evidence_ids: tuple[str, ...] = ()
    validation_status: str = "deterministic"
    prompt_hash: str | None = None
    policy_version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", _utc(self.created_at))
        object.__setattr__(self, "url", public_url(self.url))
        if not self.evidence_ids and self.validation_status == "deterministic":
            identity = sha256(
                f"{self.rule_id}\x1f{self.url}\x1f{self.evidence}".encode()
            ).hexdigest()
            object.__setattr__(self, "evidence_ids", ("evidence:" + identity,))

    @classmethod
    def create(
        cls,
        rule_id: str,
        url: str,
        severity: Severity,
        title: str,
        *,
        confidence: float = 1.0,
        description: str = "",
        recommendation: str = "",
        evidence: str = "",
        engine: str = "secman-web-check",
        model: str | None = None,
        created_at: datetime | None = None,
        identity_context: str = "",
        evidence_ids: tuple[str, ...] = (),
        validation_status: str = "deterministic",
        prompt_hash: str | None = None,
        policy_version: str | None = None,
    ) -> Finding:
        """Create a finding whose external identity is stable for rule and target."""
        url = public_url(url)
        identity_input = f"{rule_id}\N{UNIT SEPARATOR}{url}"
        if identity_context:
            identity_input += f"\N{UNIT SEPARATOR}{identity_context}"
        identity = sha256(identity_input.encode()).hexdigest()
        return cls(
            rule_id=rule_id,
            external_id=f"{rule_id}:{identity}",
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            recommendation=recommendation,
            evidence=evidence,
            url=url,
            engine=engine,
            model=model,
            created_at=_now() if created_at is None else created_at,
            evidence_ids=evidence_ids,
            validation_status=validation_status,
            prompt_hash=prompt_hash,
            policy_version=policy_version,
        )


@dataclass(frozen=True, slots=True)
class DetectedComponent:
    component_key: str
    category: ComponentCategory
    name: str
    version: str | None
    confidence: float
    evidence_type: str
    evidence: str
    source_url: str | None = None

    def __post_init__(self) -> None:
        if self.source_url:
            object.__setattr__(self, "source_url", public_url(self.source_url))

    @classmethod
    def create(
        cls,
        category: ComponentCategory,
        name: str,
        *,
        version: str | None = None,
        confidence: float,
        evidence_type: str,
        evidence: str,
        source_url: str | None = None,
    ) -> DetectedComponent:
        identity = sha256(
            f"{category.value}\N{UNIT SEPARATOR}{name.casefold()}\N{UNIT SEPARATOR}{version or ''}".encode()
        ).hexdigest()
        return cls(
            component_key=f"{category.value.lower()}:{identity}",
            category=category,
            name=name,
            version=version,
            confidence=confidence,
            evidence_type=evidence_type,
            evidence=evidence,
            source_url=source_url,
        )


@dataclass(frozen=True, slots=True)
class ExposureObservation:
    configured_url: str
    effective_url: str | None
    reachability: Reachability
    http_status: int | None
    redirect_count: int
    vantage_point: str = "secman-web-check"
    body_length: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "configured_url", public_url(self.configured_url))
        if self.effective_url:
            object.__setattr__(self, "effective_url", public_url(self.effective_url))


@dataclass(frozen=True, slots=True)
class CheckExecution:
    """An evaluated or explicitly untested evidence domain; never implies full coverage."""

    check_id: str
    url: str
    state: str  # executed-positive, executed-negative, skipped, unsupported, failed, exhausted
    evidence_ids: tuple[str, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if self.state not in {
            "executed-positive",
            "executed-negative",
            "skipped",
            "unsupported",
            "failed",
            "exhausted",
        }:
            raise ValueError("invalid check execution state")
        object.__setattr__(self, "url", public_url(self.url))


@dataclass(frozen=True, slots=True)
class ApiOperation:
    """Metadata only: parameter names/types, never example/default/session values."""

    path: str
    method: str
    source: str
    parameters: tuple[str, ...] = ()
    request_content_types: tuple[str, ...] = ()
    response_content_types: tuple[str, ...] = ()
    authenticated: bool = False
    executed: bool = False


@dataclass(frozen=True, slots=True)
class AnalysisStage:
    name: str
    state: str
    started_at: datetime
    completed_at: datetime
    model: str | None = None
    prompt_hash: str | None = None
    policy_version: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    id: str
    rule_id: str
    engine: str
    url: str
    signature: str


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    pages_scanned: int = 0
    pages_discovered: int = 0
    pages: tuple[str, ...] = ()
    crawl_requests: int = 0
    http_requests: int = 0
    crawl_complete: bool = True
    agent_actions: int = 0
    agent_complete: bool = True
    executions: tuple[CheckExecution, ...] = ()
    query_input: bool = False


@dataclass(frozen=True, slots=True)
class JavaScriptAsset:
    """Metadata retained for a fetched script; response bytes are never persisted."""

    url: str
    sha256: str
    size_bytes: int
    status_code: int
    truncated: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", public_url(self.url))


@dataclass(frozen=True, slots=True)
class TargetResult:
    target: NormalizedTarget
    status: TargetStatus
    findings: tuple[Finding, ...] = ()
    components: tuple[DetectedComponent, ...] = ()
    javascript_assets: tuple[JavaScriptAsset, ...] = ()
    exposure: ExposureObservation | None = None
    inventory_complete: bool = False
    coverage: CoverageSummary = field(default_factory=CoverageSummary)
    errors: tuple[str, ...] = ()
    complete: bool = True
    started_at: datetime = field(default_factory=_now)
    completed_at: datetime = field(default_factory=_now)
    api_operations: tuple[ApiOperation, ...] = ()
    analysis_stages: tuple[AnalysisStage, ...] = ()
    evidence_records: tuple[EvidenceRecord, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", _utc(self.started_at))
        object.__setattr__(self, "completed_at", _utc(self.completed_at))
        records = {item.id: item for item in self.evidence_records}
        for finding in self.findings:
            if finding.validation_status == "deterministic":
                for identifier in finding.evidence_ids:
                    records[identifier] = EvidenceRecord(
                        identifier,
                        finding.rule_id,
                        finding.engine,
                        public_url(finding.url),
                        finding.evidence[:512],
                    )
        object.__setattr__(self, "evidence_records", tuple(records.values()))


@dataclass(frozen=True, slots=True)
class ScanRun:
    run_id: str
    targets: tuple[TargetResult, ...]
    started_at: datetime = field(default_factory=_now)
    completed_at: datetime = field(default_factory=_now)
    profile: str = "security:passive"
    manifest_json: str = "{}"
    metrics_json: str = "{}"

    @property
    def profile_hash(self) -> str:
        return sha256(
            json.dumps(
                json.loads(self.manifest_json), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", _utc(self.started_at))
        object.__setattr__(self, "completed_at", _utc(self.completed_at))

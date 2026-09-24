"""Immutable normalized values shared by scanner stages and output adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256

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

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", _utc(self.created_at))

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
    ) -> Finding:
        """Create a finding whose external identity is stable for rule and target."""
        identity = sha256(f"{rule_id}\N{UNIT SEPARATOR}{url}".encode()).hexdigest()
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


@dataclass(frozen=True, slots=True)
class JavaScriptAsset:
    """Metadata retained for a fetched script; response bytes are never persisted."""

    url: str
    sha256: str
    size_bytes: int
    status_code: int
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class TargetResult:
    target: NormalizedTarget
    status: TargetStatus
    findings: tuple[Finding, ...] = ()
    components: tuple[DetectedComponent, ...] = ()
    javascript_assets: tuple[JavaScriptAsset, ...] = ()
    exposure: ExposureObservation | None = None
    inventory_complete: bool = False
    errors: tuple[str, ...] = ()
    complete: bool = True
    started_at: datetime = field(default_factory=_now)
    completed_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", _utc(self.started_at))
        object.__setattr__(self, "completed_at", _utc(self.completed_at))


@dataclass(frozen=True, slots=True)
class ScanRun:
    run_id: str
    targets: tuple[TargetResult, ...]
    started_at: datetime = field(default_factory=_now)
    completed_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", _utc(self.started_at))
        object.__setattr__(self, "completed_at", _utc(self.completed_at))

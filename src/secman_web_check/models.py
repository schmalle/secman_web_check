"""Immutable normalized values shared by scanner stages and output adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any


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
            created_at=_now() if created_at is None else created_at,
        )


@dataclass(frozen=True, slots=True)
class TargetResult:
    target: Any
    status: TargetStatus
    findings: tuple[Finding, ...] = ()
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

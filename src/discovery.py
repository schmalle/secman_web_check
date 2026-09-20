"""Explicit, bounded content discovery for authorized HTTP 200 targets."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .http import CollectionError, HttpCollector
from .models import Finding, Severity
from .targets import AddressDenied, NormalizedTarget, normalize_target

DEFAULT_PATHS = ("admin/", "api/", "backup/", "docs/", "health/", "login/", "robots.txt")


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    findings: tuple[Finding, ...] = ()
    errors: tuple[str, ...] = ()


def discover_paths(
    target: NormalizedTarget,
    collector: HttpCollector,
    *,
    paths: tuple[str, ...] = DEFAULT_PATHS,
) -> DiscoveryResult:
    """Probe a fixed path allowlist; this is not recursive, brute force, or fuzzing."""
    findings: list[Finding] = []
    errors: list[str] = []
    root = urlsplit(target.url)
    for path in paths[:100]:
        safe_path = path.strip().lstrip("/")
        if not safe_path or ".." in safe_path or any(char in safe_path for char in "?#\\"):
            raise ValueError("discovery paths must be safe relative paths")
        url = urlunsplit((root.scheme, root.netloc, "/" + safe_path, "", ""))
        try:
            response = collector.with_max_body_bytes(4096).collect(normalize_target(url))[-1]
        except (AddressDenied, CollectionError):
            errors.append("content discovery request failed")
            continue
        if response.status_code not in {200, 204, 301, 302, 307, 308, 401, 403}:
            continue
        severity = Severity.LOW if response.status_code in {200, 204} else Severity.INFO
        findings.append(
            Finding.create(
                "WEB-DISCOVERED-PATH",
                url,
                severity,
                "Additional web path discovered",
                description="A bounded content-discovery request found a non-missing path.",
                recommendation="Confirm the path is intended to be externally reachable.",
                evidence=f"HTTP {response.status_code} at /{safe_path}",
                engine="secman-web-check-dirbuster",
            )
        )
    return DiscoveryResult(tuple(findings), tuple(dict.fromkeys(errors)))


__all__ = ["DEFAULT_PATHS", "DiscoveryResult", "discover_paths"]

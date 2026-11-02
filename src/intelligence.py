"""Explicit OSV snapshot updates and offline, provenance-tracked npm range matching."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Any

import httpx

from .config import ScannerConfig
from .http import HttpCollector, RequestBudget, pinned_transport
from .models import DetectedComponent, Finding, Severity
from .provider_dns import resolve_allowed
from .reports.common import atomic_write
from .targets import AddressPolicy, normalize_target

_NAMES = {
    "jquery": "jQuery",
    "react": "React",
    "vue": "Vue.js",
    "angular": "AngularJS",
    "lodash": "Lodash",
    "moment": "Moment.js",
    "d3": "D3.js",
    "bootstrap": "Bootstrap",
    "tailwindcss": "Tailwind CSS",
    "bulma": "Bulma",
    "foundation-sites": "Foundation",
    "materialize-css": "Materialize CSS",
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$")


def _version(value: str) -> tuple[Any, ...]:
    match = re.fullmatch(
        r"v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?(?:-([A-Za-z0-9.-]+))?(?:\+[A-Za-z0-9.-]+)?",
        value,
    )
    if not match:
        raise ValueError("unsupported semantic version")
    major, minor, patch, pre = match.groups()
    identifiers = (
        tuple((0, int(part)) if part.isdigit() else (1, part) for part in pre.split("."))
        if pre
        else ()
    )
    return int(major), int(minor or 0), int(patch or 0), 1 if pre is None else 0, identifiers


def _affected(version: str, events: list[dict[str, str]]) -> bool:
    value = _version(version)
    active = False
    matched = False
    for event in events:
        if len(event) != 1:
            raise ValueError("invalid advisory event")
        kind, boundary = next(iter(event.items()))
        key = _version(boundary)
        if kind == "introduced":
            active = boundary == "0" or value >= key
        elif kind in {"fixed", "last_affected", "limit"}:
            if active and (value <= key if kind == "last_affected" else value < key):
                matched = True
            active = False
        else:
            raise ValueError("unsupported advisory range event")
    return matched or active


def _normalize(record: dict[str, Any]) -> dict[str, Any]:
    identifier = record.get("id")
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ValueError("invalid advisory ID")
    entries = []
    unsupported = 0
    excluded = 0
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != "npm" or package.get("name") not in _NAMES:
            excluded += 1
            continue
        ranges = []
        for span in affected.get("ranges", []):
            if span.get("type") != "SEMVER":
                unsupported += 1
                continue
            events = span.get("events", [])
            if not isinstance(events, list) or not events or len(events) > 100:
                raise ValueError("invalid advisory range")
            _affected("0.0.0", events)
            ranges.append(events)
        versions = affected.get("versions", [])
        for version in versions:
            _version(version)
        entries.append({"package": package["name"], "ranges": ranges, "versions": versions})
    return {
        "id": identifier,
        "modified": str(record.get("modified", "")),
        "withdrawn": bool(record.get("withdrawn")),
        "affected": entries,
        "unsupported": unsupported,
        "excludedPackages": excluded,
        "source": f"https://api.osv.dev/v1/vulns/{identifier}",
    }


@dataclass(frozen=True, slots=True)
class AdvisorySnapshot:
    payload_json: str
    digest: str
    fetched_at: datetime

    @property
    def stale(self) -> bool:
        return datetime.now(UTC) - self.fetched_at > timedelta(days=30)

    def provenance(self) -> dict[str, Any]:
        payload = json.loads(self.payload_json)
        return {
            "format": 1,
            "sha256": self.digest,
            "fetchedAt": self.fetched_at.isoformat(),
            "stale": self.stale,
            "sources": [item["source"] for item in payload["advisories"]],
            "unsupportedRanges": sum(item["unsupported"] for item in payload["advisories"]),
            "excludedPackages": sum(
                item.get("excludedPackages", 0) for item in payload["advisories"]
            ),
        }

    def findings(self, components: tuple[DetectedComponent, ...], url: str) -> tuple[Finding, ...]:
        result = []
        for record in json.loads(self.payload_json)["advisories"]:
            if record["withdrawn"]:
                continue
            for component in components:
                if not component.version:
                    continue
                try:
                    for entry in record["affected"]:
                        if component.name != _NAMES.get(entry["package"]):
                            continue
                        if component.version in entry["versions"] or any(
                            _affected(component.version, events) for events in entry["ranges"]
                        ):
                            result.append(
                                Finding.create(
                                    "WEB-COMPONENT-" + record["id"],
                                    url,
                                    Severity.MEDIUM,
                                    f"Potentially vulnerable {component.name} {component.version}",
                                    confidence=component.confidence,
                                    evidence=f"Advisory {record['id']}; snapshot {self.digest}",
                                    description="Detected version matches a maintained OSV affected range; exploitability is unverified.",
                                    recommendation="Review the referenced advisory and upgrade to an unaffected release.",
                                    engine="secman-web-check-components",
                                )
                            )
                except ValueError:
                    continue  # unknown detector versions never establish vulnerability
        return tuple({item.external_id: item for item in result}.values())


def load_snapshot(path: Path, expected_sha256: str) -> AdvisorySnapshot:
    if path.stat().st_size > 5_000_000:
        raise ValueError("advisory snapshot exceeds 5 MB")
    raw = path.read_bytes()
    if (
        not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        or sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError("advisory snapshot checksum mismatch")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported advisory snapshot")
    fetched = datetime.fromisoformat(payload["fetchedAt"])
    if fetched.tzinfo is None or fetched > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("invalid advisory timestamp")
    records = payload.get("advisories")
    if not isinstance(records, list) or not records or len(records) > 500:
        raise ValueError("invalid advisory snapshot records")
    for record in records:
        if (
            not _ID.fullmatch(record["id"])
            or record["source"] != f"https://api.osv.dev/v1/vulns/{record['id']}"
        ):
            raise ValueError("invalid advisory provenance")
        for entry in record["affected"]:
            if entry["package"] not in _NAMES:
                raise ValueError("unsupported advisory package")
            for events in entry["ranges"]:
                _affected("0.0.0", events)
    return AdvisorySnapshot(raw.decode(), expected_sha256, fetched)


def _package_records(package: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    page_token = ""
    for _ in range(10):
        deadline = monotonic() + 30.0
        target = normalize_target("https://api.osv.dev")
        addresses = resolve_allowed(target, AddressPolicy(), deadline)
        body: dict[str, Any] = {"package": {"name": package, "ecosystem": "npm"}}
        if page_token:
            body["page_token"] = page_token
        with (
            httpx.Client(
                transport=pinned_transport(target, addresses, deadline=deadline),
                timeout=30.0,
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream("POST", "https://api.osv.dev/v1/query", json=body) as response,
        ):
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes(chunk_size=16384):
                raw.extend(chunk)
                if len(raw) > 1_000_000 or monotonic() >= deadline:
                    raise ValueError("OSV query budget exceeded")
            document = json.loads(raw)
        if not isinstance(document, dict) or not isinstance(document.get("vulns", []), list):
            raise TypeError("invalid OSV package result")
        records.extend(_normalize(record) for record in document.get("vulns", []))
        if len(records) > 500:
            raise ValueError("OSV package exceeds 500 advisory limit")
        token = document.get("next_page_token", "")
        if not isinstance(token, str) or len(token) > 4096:
            raise ValueError("invalid OSV pagination token")
        if not token:
            return records
        if token == page_token:
            raise ValueError("OSV pagination did not progress")
        page_token = token
    raise ValueError("OSV query pagination budget exhausted")


def update_snapshot(ids: tuple[str, ...], path: Path, *, packages: tuple[str, ...] = ()) -> str:
    """Explicit public package/ID updates; no detected asset inventory leaves the scan."""
    if (
        not ids
        and not packages
        or len(ids) > 500
        or any(not _ID.fullmatch(item) for item in ids)
        or any(package not in _NAMES for package in packages)
    ):
        raise ValueError("select valid advisory IDs or supported npm package names")
    collector = HttpCollector(
        ScannerConfig(max_body_bytes=1_000_000),
        budget=RequestBudget(500, 1.0),
        allowed_origins=frozenset({"https://api.osv.dev"}),
    )
    records = []
    for package in sorted(set(packages)):
        records.extend(_package_records(package))
    for identifier in sorted(set(ids)):
        response = collector.collect(
            normalize_target(f"https://api.osv.dev/v1/vulns/{identifier}")
        )[-1]
        if response.status_code != 200 or response.truncated:
            raise ValueError("OSV update failed or exceeded response budget")
        raw = json.loads(response.body)
        if not isinstance(raw, dict) or raw.get("id") != identifier:
            raise ValueError("OSV returned an unexpected advisory")
        records.append(_normalize(raw))
    unique = {record["id"]: record for record in records}
    if not unique or len(unique) > 500:
        raise ValueError("snapshot requires 1–500 advisories; previous snapshot retained")
    payload = (
        json.dumps(
            {
                "version": 1,
                "fetchedAt": datetime.now(UTC).isoformat(),
                "advisories": [unique[key] for key in sorted(unique)],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    if len(payload.encode()) > 5_000_000:
        raise ValueError("advisory snapshot exceeds 5 MB")
    atomic_write(path, payload)
    return sha256(payload.encode()).hexdigest()

"""Conservative comparison of two local machine reports."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..models import public_url


def _load(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 20_000_000:
        raise ValueError("report exceeds the 20 MB comparison limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("targets"), list):
        raise TypeError("comparison input must be a scanner JSON report")
    return document


def _targets(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for target in document["targets"]:
        if not isinstance(target, dict) or not isinstance(target.get("url"), str):
            raise TypeError("comparison input contains an invalid target")
        coverage = target.get("coverage", {})
        if not isinstance(coverage, dict) or not isinstance(coverage.get("executions", []), list):
            raise TypeError("comparison input contains invalid coverage")
        url = public_url(target["url"])
        if url in result:
            raise ValueError("comparison input contains duplicate targets")
        result[url] = target
    return result


def _ids(target: dict[str, Any]) -> set[str]:
    rows = target.get("findings")
    if not isinstance(rows, list):
        raise TypeError("comparison input contains invalid findings")
    ids = {
        row["externalId"]
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("externalId"), str)
    }
    if len(ids) != len(rows):
        raise ValueError("comparison input contains duplicate or invalid finding IDs")
    return ids


def compare_reports(old_path: Path, new_path: Path) -> dict[str, Any]:
    """Only a complete matching passive profile may confirm an absent finding."""
    old = _load(old_path)
    new = _load(new_path)
    previous = _targets(old)
    current = _targets(new)
    profiles_match = (
        isinstance(old.get("coverageManifest"), dict)
        and old["coverageManifest"].get("version") == 1
        and old.get("coverageManifest") == new.get("coverageManifest")
        and old.get("profileHash")
        == sha256(
            json.dumps(old["coverageManifest"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        and old.get("profileHash") == new.get("profileHash")
        and old.get("profileHash") is not None
        and old.get("profile") == new.get("profile") == "security:passive"
    )
    introduced: set[str] = set()
    resolved: set[str] = set()
    unconfirmed: set[str] = set()
    unchanged: set[str] = set()
    for url in sorted(previous.keys() | current.keys()):
        before = _ids(previous[url]) if url in previous else set()
        after = _ids(current[url]) if url in current else set()
        introduced.update(after - before)
        unchanged.update(before & after)
        missing = before - after
        advisory = {
            row["externalId"]
            for row in previous.get(url, {}).get("findings", [])
            if row.get("validationStatus", "deterministic") != "deterministic"
            or row.get("ruleId", row["externalId"]).startswith(("LLM-", "VISUAL-"))
        }
        executions = {
            (row.get("check_id"), public_url(row.get("url", url))): row.get("state")
            for row in current.get(url, {}).get("coverage", {}).get("executions", [])
            if isinstance(row, dict)
        }
        unevaluated = set()
        for row in previous.get(url, {}).get("findings", []):
            identifier = row["externalId"]
            rule = row.get("ruleId", identifier.split(":", 1)[0])
            domain = "components:advisories" if rule.startswith("WEB-COMPONENT-") else rule
            if identifier in missing and executions.get(
                (domain, public_url(row.get("url", url)))
            ) not in {
                "executed-positive",
                "executed-negative",
            }:
                unevaluated.add(identifier)
        if previous.get(url, {}).get("coverage", {}).get("queryInput") or current.get(url, {}).get(
            "coverage", {}
        ).get("queryInput"):
            unevaluated.update(missing)
        exposure = current.get(url, {}).get("exposure")
        if isinstance(exposure, dict) and (
            exposure.get("httpStatus") != 200
            or exposure.get("redirectCount", 0) != 0
            or exposure.get("configuredUrl") != exposure.get("effectiveUrl")
        ):
            unevaluated.update(missing)
        unconfirmed.update(missing & unevaluated)
        missing -= unevaluated
        unconfirmed.update(missing & advisory)
        missing -= advisory
        if (
            profiles_match
            and url in current
            and current[url].get("complete") is True
            and current[url].get("status") == "SUCCESS"
        ):
            resolved.update(missing)
        else:
            unconfirmed.update(missing)
    return {
        "oldRunId": old.get("runId"),
        "newRunId": new.get("runId"),
        "comparableCoverage": profiles_match,
        "introduced": sorted(introduced),
        "resolved": sorted(resolved),
        "unconfirmedAbsent": sorted(unconfirmed),
        "unchangedCount": len(unchanged),
    }

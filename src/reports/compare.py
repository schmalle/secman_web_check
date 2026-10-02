"""Conservative comparison of two local machine reports."""

from __future__ import annotations

import json
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
    profiles_match = old.get("profile") == new.get("profile") == "security:passive"
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

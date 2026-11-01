"""Repeatable detection measurements over explicitly labeled synthetic response fixtures."""

from __future__ import annotations

import json
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any

from .checks import PASSIVE_CHECKS, CheckContext
from .checks.registry import RULES
from .components import detect_components, find_component_vulnerabilities
from .coverage import revision
from .http import HttpRequest, HttpResponseEvidence
from .models import public_url
from .targets import normalize_target


def evaluate(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 2_000_000:
        raise ValueError("evaluation corpus exceeds 2 MB")
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document.get("cases") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("version") != 1
        or not isinstance(cases, list)
        or not 1 <= len(cases) <= 500
    ):
        raise ValueError("invalid evaluation corpus")
    results = []
    totals: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    labels: dict[str, set[str]] = defaultdict(set)
    ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or case.get("label") not in {"vulnerable", "safe"}:
            raise ValueError("evaluation requires vulnerable/safe labels")
        identifier, group = case["id"], case["class"]
        if identifier in ids:
            raise ValueError("duplicate evaluation fixture ID")
        ids.add(identifier)
        labels[group].add(case["label"])
        expected, eligible = set(case["expected"]), set(case["eligible"])
        if (
            not eligible
            or not expected <= eligible
            or bool(expected) != (case["label"] == "vulnerable")
            or any(
                rule not in RULES and not rule.startswith("WEB-COMPONENT-CVE-") for rule in eligible
            )
        ):
            raise ValueError("invalid evaluation expectations")
        url = normalize_target(case.get("url", "https://fixture.example/")).url
        response = HttpResponseEvidence(
            HttpRequest("GET", url),
            case.get("status", 200),
            tuple((str(name).lower(), str(value)) for name, value in case.get("headers", [])),
            str(case.get("body", "")).encode(),
            False,
            0.0,
        )
        findings = [
            finding for check in PASSIVE_CHECKS for finding in check(CheckContext(response))
        ]
        findings.extend(find_component_vulnerabilities(detect_components(response), url))
        actual = {finding.rule_id for finding in findings} & eligible
        counts = {
            "tp": len(actual & expected),
            "fp": len(actual - expected),
            "fn": len(expected - actual),
            "tn": len(eligible - expected - actual),
        }
        for name, value in counts.items():
            totals[group][name] += value
        results.append(
            {
                "id": identifier,
                "class": group,
                "label": case["label"],
                "url": public_url(url),
                "expected": sorted(expected),
                "actual": sorted(actual),
                **counts,
            }
        )
    if any(value != {"vulnerable", "safe"} for value in labels.values()):
        raise ValueError("each measured class requires both vulnerable and safe fixtures")
    measured = {}
    for group, counts in sorted(totals.items()):
        measured[group] = {
            **counts,
            "precision": counts["tp"] / (counts["tp"] + counts["fp"])
            if counts["tp"] + counts["fp"]
            else 0.0,
            "recall": counts["tp"] / (counts["tp"] + counts["fn"])
            if counts["tp"] + counts["fn"]
            else 0.0,
        }
    return {
        "version": 1,
        "corpusSha256": sha256(path.read_bytes()).hexdigest(),
        "evaluatorRevision": revision(
            "evaluation.py",
            "checks/headers.py",
            "checks/cookies.py",
            "checks/cors.py",
            "checks/content.py",
            "components.py",
        ),
        "scope": "Synthetic response fixtures; not real-world detection assurance",
        "cases": results,
        "perClass": measured,
        "passed": all(value["fp"] == value["fn"] == 0 for value in measured.values()),
    }

"""Versioned, reproducible execution manifests and evidence-domain outcomes."""

from __future__ import annotations

import json
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Any

from .config import ScannerConfig
from .models import CheckExecution, Finding


def revision(*names: str) -> str:
    digest = sha256()
    for name in names:
        digest.update(name.encode())
        digest.update((Path(__file__).parent / name).read_bytes())
    return digest.hexdigest()


def manifest(config: ScannerConfig, **options: Any) -> str:
    """Never include keys, raw targets, example values or prompt text in provenance."""
    return json.dumps(
        {
            "version": 1,
            "scannerVersion": "0.3.0",
            "config": asdict(config),
            "rulesRevision": revision(
                "checks/registry.py",
                "checks/active.py",
                "checks/headers.py",
                "checks/cookies.py",
                "checks/cors.py",
                "checks/content.py",
                "checks/redirects.py",
                "tls.py",
            ),
            "detectorRevision": revision("components.py"),
            "engineRevision": revision(
                "models.py",
                "javascript.py",
                "coverage.py",
                "config.py",
                "external_worker.py",
                "http.py",
                "targets.py",
                "tls_transport.py",
                "orchestrator.py",
                "checks/__init__.py",
                "agent.py",
                "visual.py",
                "system_review.py",
                "provider.py",
                "provider_dns.py",
                "browser_discovery.py",
                "api_inventory.py",
                "intelligence.py",
                "external_scanners.py",
                "external_profile.py",
                "external_proxy.py",
            ),
            "options": options,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def outcome(check_id: str, url: str, findings: tuple[Finding, ...]) -> CheckExecution:
    return CheckExecution(
        check_id,
        url,
        "executed-positive" if findings else "executed-negative",
        tuple(item.external_id for item in findings),
    )

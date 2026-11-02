"""Strict adapters for explicitly enabled, non-destructive open-source scanners."""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .external_profile import ExternalProfile, confined_run, verified_copy
from .external_proxy import scoped_proxy
from .models import Finding, Severity
from .targets import AddressPolicy, NormalizedTarget, resolve_allowed
from .traffic import TrafficController

SUPPORTED_SCANNERS = frozenset({"nuclei", "nikto"})


class ExternalScannerError(RuntimeError):
    """An external scanner could not be run safely or parsed."""


@dataclass(frozen=True, slots=True)
class ExternalScanResult:
    findings: tuple[Finding, ...] = ()
    errors: tuple[str, ...] = ()


def _rule(value: object) -> str:
    result = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", result):
        raise ExternalScannerError("invalid external rule identity")
    return result


def _severity(value: str) -> Severity:
    return Severity.__members__.get(value.upper(), Severity.INFO)


def _nuclei(
    target: NormalizedTarget, output: Path, timeout: float, profile: ExternalProfile, port: int
) -> list[Finding]:
    entry = profile.entry("nuclei")
    executable = verified_copy(entry, output.parent / "nuclei")
    templates = tuple(
        verified_copy(asset, output.parent / f"template-{index}.yaml")
        for index, asset in enumerate(entry["assets"])
    )
    command = [
        str(executable),
        "-u",
        target.url,
        "-proxy",
        f"http://127.0.0.1:{port}",
        "-jsonl",
        "-o",
        str(output),
        "-disable-update-check",
        "-no-interactsh",
        "-disable-redirects",
        "-omit-raw",
        "-omit-template",
        "-no-stdin",
        "-rate-limit",
        "1",
        "-bulk-size",
        "1",
        "-concurrency",
        "1",
        "-timeout",
        "10",
    ]
    for template in templates:
        command.extend(("-t", str(template)))
    confined_run(command, output, timeout, port, (executable, *templates))
    findings: list[Finding] = []
    for line in output.read_text(encoding="utf-8", errors="replace").splitlines()[:500]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            raise ExternalScannerError("invalid external row")
        info = row.get("info", {})
        if not isinstance(info, dict):
            raise ExternalScannerError("invalid external metadata")
        rule = _rule(row.get("template-id", "unknown"))
        findings.append(
            Finding.create(
                f"NUCLEI-{rule}",
                target.url,
                _severity(str(info.get("severity", "info"))),
                "Reviewed Nuclei template observation",
                description="Nuclei safe-template observation.",
                evidence="Reviewed template matched; profile " + profile.digest,
                recommendation="Review the referenced Nuclei template and remediate if applicable.",
                engine="nuclei",
            )
        )
    return findings


def _nikto(
    target: NormalizedTarget, output: Path, timeout: float, profile: ExternalProfile, port: int
) -> list[Finding]:
    entry = profile.entry("nikto")
    executable = verified_copy(entry, output.parent / "nikto")
    assets = tuple(
        verified_copy(asset, output.parent / Path(asset["path"]).name) for asset in entry["assets"]
    )
    command = [
        str(executable),
        "-host",
        target.url,
        "-useproxy",
        f"http://127.0.0.1:{port}",
        "-Tuning",
        "123b",
        "-Pause",
        "1",
        "-maxtime",
        f"{max(1, int(timeout))}s",
        "-Format",
        "json",
        "-output",
        str(output),
        "-nointeractive",
    ]
    confined_run(command, output, timeout, port, (executable, *assets))
    try:
        document = json.loads(output.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as error:
        raise ExternalScannerError("nikto returned invalid JSON") from error
    rows = document.get("vulnerabilities", []) if isinstance(document, dict) else []
    return [
        Finding.create(
            "NIKTO-" + _rule(row.get("id", "observation")),
            target.url,
            Severity.LOW,
            "Nikto web-server observation",
            description="Pinned Nikto profile observation; human validation required.",
            recommendation="Review and harden the exposed web-server behavior.",
            evidence="Reviewed profile " + profile.digest,
            engine="nikto",
        )
        for row in rows[:500]
        if isinstance(row, dict)
    ]


def scan_with_external(
    target: NormalizedTarget,
    scanners: tuple[str, ...],
    *,
    policy: AddressPolicy,
    timeout_seconds: float = 120.0,
    profile: ExternalProfile | None = None,
    traffic: TrafficController | None = None,
) -> ExternalScanResult:
    """Run selected safe profiles against one freshly validated and IP-pinned address."""
    if profile is None:
        return ExternalScanResult(
            errors=("External scans require a checksum-pinned reviewed profile",)
        )
    if urlsplit(target.url).path != "/" or urlsplit(target.url).query:
        return ExternalScanResult(
            errors=("External scans require an explicitly authorized origin-root target",)
        )
    unknown = set(scanners) - SUPPORTED_SCANNERS
    if unknown:
        raise ValueError(f"unsupported external scanner: {min(unknown)}")
    findings: list[Finding] = []
    errors: list[str] = []
    for scanner in dict.fromkeys(scanners):
        try:
            # Resolve immediately before every process and pass only the approved literal.
            resolve_allowed(target, policy)
            with (
                tempfile.TemporaryDirectory(prefix="secman-web-check-") as directory,
                scoped_proxy(target, policy, traffic, timeout_seconds) as port,
            ):
                output = Path(directory) / f"{scanner}.json"
                findings.extend(
                    _nuclei(target, output, timeout_seconds, profile, port)
                    if scanner == "nuclei"
                    else _nikto(target, output, timeout_seconds, profile, port)
                )
        except (ExternalScannerError, OSError, RuntimeError, ValueError):
            errors.append(f"{scanner} scan failed")
    return ExternalScanResult(tuple(findings), tuple(errors))


__all__ = ["SUPPORTED_SCANNERS", "ExternalScanResult", "ExternalScannerError", "scan_with_external"]

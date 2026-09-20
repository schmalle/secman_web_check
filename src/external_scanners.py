"""Strict adapters for explicitly enabled, non-destructive open-source scanners."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .models import Finding, Severity
from .targets import AddressPolicy, NormalizedTarget, resolve_allowed

SUPPORTED_SCANNERS = frozenset({"nuclei", "nikto"})


class ExternalScannerError(RuntimeError):
    """An external scanner could not be run safely or parsed."""


@dataclass(frozen=True, slots=True)
class ExternalScanResult:
    findings: tuple[Finding, ...] = ()
    errors: tuple[str, ...] = ()


def _pinned_target(target: NormalizedTarget, address: str) -> str:
    host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    port = f":{target.port}" if target.port is not None else ""
    return f"{target.scheme}://{host}{port}/"


def _severity(value: str) -> Severity:
    return Severity.__members__.get(value.upper(), Severity.INFO)


def _run(command: list[str], output: Path, timeout: float) -> None:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExternalScannerError("external scanner execution failed") from error
    if completed.returncode not in {0, 1} or not output.exists():
        raise ExternalScannerError("external scanner returned an unusable result")


def _nuclei(target: NormalizedTarget, address: str, output: Path, timeout: float) -> list[Finding]:
    executable = shutil.which("nuclei")
    if executable is None:
        raise ExternalScannerError("nuclei executable is not installed")
    authority = target.host if target.port is None else f"{target.host}:{target.port}"
    command = [
        executable,
        "-u",
        _pinned_target(target, address),
        "-sni",
        target.host,
        "-H",
        f"Host: {authority}",
        "-jsonl",
        "-o",
        str(output),
        "-disable-update-check",
        "-no-interactsh",
        "-tags",
        "tech,misconfig,exposure",
        "-exclude-tags",
        "dos,fuzz,intrusive",
        "-rate-limit",
        "2",
        "-bulk-size",
        "1",
        "-concurrency",
        "1",
        "-timeout",
        "10",
    ]
    _run(command, output, timeout)
    findings: list[Finding] = []
    for line in output.read_text(encoding="utf-8", errors="replace").splitlines()[:500]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {}) if isinstance(row, dict) else {}
        rule = str(row.get("template-id", "unknown"))
        findings.append(
            Finding.create(
                f"NUCLEI-{rule}",
                target.url,
                _severity(str(info.get("severity", "info"))),
                str(info.get("name", rule))[:300],
                description="Nuclei safe-template observation.",
                evidence=str(row.get("matcher-name", "template matched"))[:1000],
                recommendation="Review the referenced Nuclei template and remediate if applicable.",
                engine="nuclei",
            )
        )
    return findings


def _nikto(target: NormalizedTarget, address: str, output: Path, timeout: float) -> list[Finding]:
    executable = shutil.which("nikto")
    if executable is None:
        raise ExternalScannerError("nikto executable is not installed")
    command = [
        executable,
        "-host",
        address,
        "-vhost",
        target.host,
        "-port",
        str(target.port or (443 if target.scheme == "https" else 80)),
        "-Tuning",
        "123b",
        "-maxtime",
        f"{max(1, int(timeout))}s",
        "-Format",
        "json",
        "-output",
        str(output),
        "-nointeractive",
    ]
    if target.scheme == "https":
        command.append("-ssl")
    _run(command, output, timeout + 5)
    try:
        document = json.loads(output.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as error:
        raise ExternalScannerError("nikto returned invalid JSON") from error
    rows = document.get("vulnerabilities", []) if isinstance(document, dict) else []
    return [
        Finding.create(
            f"NIKTO-{row.get('id', 'observation')!s}",
            target.url,
            Severity.LOW,
            "Nikto web-server observation",
            description=str(row.get("msg", ""))[:2000],
            recommendation="Review and harden the exposed web-server behavior.",
            evidence=str(row.get("url", "/"))[:1000],
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
) -> ExternalScanResult:
    """Run selected safe profiles against one freshly validated and IP-pinned address."""
    unknown = set(scanners) - SUPPORTED_SCANNERS
    if unknown:
        raise ValueError(f"unsupported external scanner: {min(unknown)}")
    findings: list[Finding] = []
    errors: list[str] = []
    for scanner in dict.fromkeys(scanners):
        try:
            # Resolve immediately before every process and pass only the approved literal.
            address = resolve_allowed(target, policy)[0]
            with tempfile.TemporaryDirectory(prefix="secman-web-check-") as directory:
                output = Path(directory) / f"{scanner}.json"
                findings.extend(
                    _nuclei(target, address, output, timeout_seconds)
                    if scanner == "nuclei"
                    else _nikto(target, address, output, timeout_seconds)
                )
        except (ExternalScannerError, OSError, ValueError):
            errors.append(f"{scanner} scan failed")
    return ExternalScanResult(tuple(findings), tuple(errors))


__all__ = ["SUPPORTED_SCANNERS", "ExternalScanResult", "ExternalScannerError", "scan_with_external"]

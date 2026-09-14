"""Fixed, opt-in active probes over the same policy-enforcing HTTP collector."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from ..http import CollectionError, HttpCollector, HttpResponseEvidence
from ..models import Finding
from ..targets import AddressDenied, normalize_target
from .registry import RULES, CheckContext


@dataclass(frozen=True, slots=True)
class ActiveProbe:
    rule_id: str
    method: str
    path: str
    max_body_bytes: int = 32_768
    origin: str | None = None


@dataclass(frozen=True, slots=True)
class ActiveCheckResult:
    findings: tuple[Finding, ...] = ()
    errors: tuple[str, ...] = ()


ACTIVE_PROBES = (
    ActiveProbe("WEB-ACTIVE-TRACE-REFLECTION", "TRACE", "/", origin="https://scanner.invalid"),
    ActiveProbe("WEB-ACTIVE-UNSAFE-METHODS", "OPTIONS", "/"),
    ActiveProbe("WEB-ACTIVE-ENV-EXPOSED", "GET", "/.env"),
    ActiveProbe("WEB-ACTIVE-GIT-EXPOSED", "GET", "/.git/HEAD"),
    ActiveProbe("WEB-ACTIVE-SERVER-STATUS-EXPOSED", "GET", "/server-status"),
    ActiveProbe("WEB-ACTIVE-CONFIG-BACKUP-EXPOSED", "GET", "/wp-config.php.bak"),
)


def _probe_url(base_url: str, path: str) -> str:
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _matches(probe: ActiveProbe, response: HttpResponseEvidence) -> bool:
    if response.status_code != 200 or response.truncated:
        return False
    text = response.body.decode("utf-8", errors="replace")[: probe.max_body_bytes]
    headers = {name.lower(): value.lower() for name, value in response.headers}
    if probe.rule_id == "WEB-ACTIVE-TRACE-REFLECTION":
        return "https://scanner.invalid" in text
    if probe.rule_id == "WEB-ACTIVE-UNSAFE-METHODS":
        methods = {item.strip().upper() for item in headers.get("allow", "").split(",")}
        return bool(methods & {"PUT", "DELETE", "PATCH"})
    if probe.rule_id == "WEB-ACTIVE-ENV-EXPOSED":
        names = re.findall(r"(?m)^(?:APP_KEY|DATABASE_URL|DB_PASSWORD|SECRET_KEY)\s*=", text)
        return len(set(names)) >= 2
    if probe.rule_id == "WEB-ACTIVE-GIT-EXPOSED":
        return bool(re.fullmatch(r"ref:\s+refs/(?:heads|tags)/[A-Za-z0-9._/-]+\s*", text))
    if probe.rule_id == "WEB-ACTIVE-SERVER-STATUS-EXPOSED":
        return "server version:" in text.lower() and "server uptime:" in text.lower()
    if probe.rule_id == "WEB-ACTIVE-CONFIG-BACKUP-EXPOSED":
        return "<?php" in text and "DB_NAME" in text and "DB_PASSWORD" in text
    return False


def run_active_checks(
    context: CheckContext,
    collector: HttpCollector,
    *,
    enabled: bool,
) -> ActiveCheckResult:
    """Run only the fixed catalogue when explicitly enabled."""
    if not enabled:
        return ActiveCheckResult()
    findings: list[Finding] = []
    errors: list[str] = []
    for probe in ACTIVE_PROBES:
        headers = {} if probe.origin is None else {"Origin": probe.origin}
        try:
            responses = collector.with_max_body_bytes(probe.max_body_bytes).collect(
                normalize_target(_probe_url(context.response.url, probe.path)),
                method=probe.method,
                headers=headers,
            )
        except (AddressDenied, CollectionError):
            errors.append(f"Active {probe.method} {probe.path} probe failed")
            continue
        response = responses[-1]
        if _matches(probe, response):
            findings.append(
                RULES[probe.rule_id].finding(
                    CheckContext(response),
                    f"Fixed {probe.method} probe matched {probe.path} signature",
                )
            )
    return ActiveCheckResult(tuple(findings), tuple(errors))


__all__ = ["ACTIVE_PROBES", "ActiveCheckResult", "ActiveProbe", "run_active_checks"]

"""Passive header policy inspection; duplicate response fields remain ordered."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Finding
from .registry import RULES, CheckContext


def _directives(policy: str) -> dict[str, tuple[str, ...]]:
    directives: dict[str, tuple[str, ...]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tuple(tokens[1:]))
    return directives


def _source_risks(sources: tuple[str, ...] | None) -> set[str]:
    if sources is None:
        return {"unrestricted", "broad-source", "unsafe-inline", "unsafe-eval"}
    risks = set()
    if any(
        source in {"*", "http:", "https:", "data:"} or source.startswith("http://")
        for source in sources
    ):
        risks.add("broad-source")
    if "'unsafe-eval'" in sources:
        risks.add("unsafe-eval")
    if "'unsafe-inline'" in sources and not any(
        source.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for source in sources
    ):
        risks.add("unsafe-inline")
    return risks


def _script_risks(policy: dict[str, tuple[str, ...]]) -> set[str]:
    scripts = policy.get("script-src", policy.get("default-src"))
    element_risks = _source_risks(policy.get("script-src-elem", scripts))
    attribute_risks = _source_risks(policy.get("script-src-attr", scripts))
    risks = {f"element:{risk}" for risk in element_risks - {"unsafe-eval"}}
    if "unsafe-inline" in attribute_risks:
        risks.add("attribute:unsafe-inline")
    if "unsafe-eval" in _source_risks(scripts):
        risks.add("unsafe-eval")
    return risks


def _strong_hsts(header: str) -> bool:
    ages = [
        part.partition("=")[2].strip()
        for part in header.split(";")
        if part.partition("=")[0].strip().lower() == "max-age"
    ]
    if len(ages) != 1 or not re.fullmatch(r'(?:[0-9]+|"[0-9]+")', ages[0]):
        return False
    # Compare a capped integer after stripping leading zeros, so attacker-supplied
    # long decimals never hit Python's integer conversion limit.
    digits = ages[0].strip('"').lstrip("0") or "0"
    return len(digits) > 8 or int(digits) >= 15_552_000


def check_headers(context: CheckContext) -> tuple[Finding, ...]:
    findings = []

    def add(suffix: str, evidence: str) -> None:
        findings.append(RULES[f"WEB-HEADER-{suffix}"].finding(context, evidence))

    values = context.header_values
    if urlsplit(context.response.url).scheme == "https":
        hsts = values("strict-transport-security")
        if not hsts:
            add("HSTS-MISSING", "Strict-Transport-Security: absent")
        elif not _strong_hsts(hsts[0]):
            add("HSTS-WEAK", "Strict-Transport-Security: max-age is invalid or below 15552000")

    nosniff = values("x-content-type-options")
    if not nosniff or nosniff[0].strip().lower() != "nosniff":
        add("NOSNIFF-MISSING", "X-Content-Type-Options: nosniff absent or invalid")

    if context.is_html:
        policies = [
            _directives(policy)
            for header in values("content-security-policy")
            for policy in header.split(",")
            if policy.strip()
        ]
        if not policies:
            add("CSP-MISSING", "Content-Security-Policy: no enforced policy")
        elif set.intersection(*(_script_risks(policy) for policy in policies)):
            add(
                "CSP-UNSAFE",
                "Content-Security-Policy: shared unsafe script-src/default-src capability",
            )

        frame_restricted = any(
            policy.get("frame-ancestors")
            and not any(source in {"*", "http:", "https:"} for source in policy["frame-ancestors"])
            for policy in policies
        )
        xfo = values("x-frame-options")
        if not frame_restricted and not (xfo and xfo[0].strip().upper() in {"DENY", "SAMEORIGIN"}):
            add("FRAMING-MISSING", "CSP frame-ancestors and X-Frame-Options: no restrictive policy")

        recognized = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "same-origin",
            "origin",
            "strict-origin",
            "origin-when-cross-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        }
        referrers = [
            token.strip().lower()
            for header in values("referrer-policy")
            for token in header.split(",")
            if token.strip().lower() in recognized
        ]
        if not referrers:
            add("REFERRER-POLICY-MISSING", "Referrer-Policy: no recognized policy")
        elif referrers[-1] in {
            "unsafe-url",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
        }:
            add("REFERRER-POLICY-WEAK", "Referrer-Policy: URL or downgrade disclosure permitted")

        if not any(value.strip() for value in values("permissions-policy")):
            add("PERMISSIONS-POLICY-MISSING", "Permissions-Policy: absent")
        for name, suffix, accepted in (
            ("cross-origin-opener-policy", "COOP", {"same-origin", "same-origin-allow-popups"}),
            ("cross-origin-embedder-policy", "COEP", {"require-corp", "credentialless"}),
            ("cross-origin-resource-policy", "CORP", {"same-origin", "same-site"}),
        ):
            headers = values(name)
            if not headers or headers[0].split(";", 1)[0].strip().lower() not in accepted:
                add(f"{suffix}-MISSING", f"{name}: no restrictive policy")

    cache = {part.strip().lower() for value in values("cache-control") for part in value.split(",")}
    if values("set-cookie") and "no-store" not in cache:
        add("CACHE-SENSITIVE", "Set-Cookie present; Cache-Control no-store absent")
    disclosed = [
        name for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version") if values(name)
    ]
    if any(re.search(r"/\s*\d", value) for value in values("server")):
        disclosed.append("server")
    if disclosed:
        add("DISCLOSURE", "Technology disclosure headers: " + ", ".join(disclosed))
    return tuple(findings)

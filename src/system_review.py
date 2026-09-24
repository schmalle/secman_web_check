"""Explicit OpenRouter-backed review of sanitized scan evidence."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx

from .http import pinned_transport
from .models import Finding, ScanRun, Severity, TargetResult
from .targets import AddressPolicy, normalize_target, resolve_allowed


@dataclass(frozen=True, slots=True)
class ReviewOptions:
    prompt_path: Path
    api_key: str
    model: str = "anthropic/claude-sonnet-4.5"
    base_url: str = "https://openrouter.ai/api/v1"
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ValueError("system review requires OPENROUTER_API_KEY")
        if not self.base_url.startswith("https://"):
            raise ValueError("OpenRouter base URL must use HTTPS")
        if self.timeout_seconds <= 0:
            raise ValueError("OpenRouter timeout must be positive")


def default_prompt_path() -> Path:
    return Path(__file__).with_name("prompts") / "system-review.txt"


def load_prompt(path: Path) -> str:
    prompt = path.read_text(encoding="utf-8").strip()
    if not prompt:
        raise ValueError("system review prompt file must not be empty")
    return prompt


def _evidence(target: TargetResult) -> dict[str, Any]:
    exposure = target.exposure
    return {
        "url": target.target.url,
        "awsAccountNumber": target.target.aws_account_number,
        "status": target.status.value,
        "exposure": None
        if exposure is None
        else {
            "effectiveUrl": exposure.effective_url,
            "reachability": exposure.reachability.value,
            "httpStatus": exposure.http_status,
            "redirectCount": exposure.redirect_count,
            "bodyLength": exposure.body_length,
        },
        "components": [
            {
                "category": component.category.value,
                "name": component.name,
                "version": component.version,
                "evidence": component.evidence,
            }
            for component in target.components
        ],
        "javascriptAssets": [
            {
                "url": asset.url,
                "sha256": asset.sha256,
                "sizeBytes": asset.size_bytes,
                "statusCode": asset.status_code,
                "truncated": asset.truncated,
            }
            for asset in target.javascript_assets
        ],
        "deterministicFindings": [
            {
                "ruleId": finding.rule_id,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
            }
            for finding in target.findings
        ],
        "errors": list(target.errors),
    }


def _parse(payload: Mapping[str, Any], target: TargetResult, model: str) -> tuple[Finding, ...]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("OpenRouter returned no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise TypeError("OpenRouter returned no text")
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", content, re.DOTALL)
    document = json.loads(fenced.group(1) if fenced else content)
    rows = document.get("findings", []) if isinstance(document, dict) else []
    if not isinstance(rows, list):
        raise TypeError("system review findings must be a list")
    findings: list[Finding] = []
    for row in rows[:100]:
        if not isinstance(row, dict) or not str(row.get("title", "")).strip():
            continue
        severity = Severity.__members__.get(str(row.get("severity", "INFO")).upper(), Severity.INFO)
        try:
            confidence = max(0.0, min(1.0, float(row.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        category = re.sub(r"[^a-z0-9-]+", "-", str(row.get("category", "review")).lower())
        findings.append(
            Finding.create(
                f"LLM-{category.strip('-') or 'review'}",
                target.target.url,
                severity,
                str(row["title"])[:300],
                confidence=confidence,
                description=str(row.get("description", ""))[:2000],
                recommendation=str(row.get("recommendation", ""))[:2000],
                evidence=str(row.get("evidence", ""))[:2000],
                engine="secman-web-check-openrouter",
                model=model,
            )
        )
    return tuple(findings)


def review_run(run: ScanRun, options: ReviewOptions) -> ScanRun:
    """Review each target's sanitized evidence and merge returned findings."""
    prompt = load_prompt(options.prompt_path)
    provider = normalize_target(options.base_url)
    addresses = resolve_allowed(provider, AddressPolicy())
    reviewed: list[TargetResult] = []
    with httpx.Client(
        headers={"Authorization": f"Bearer {options.api_key}"},
        timeout=options.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
        transport=pinned_transport(provider, addresses),
    ) as client:
        for target in run.targets:
            body = {
                "model": options.model,
                "temperature": 0,
                "max_tokens": 3000,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": prompt},
                    {
                        "role": "user",
                        "content": json.dumps(_evidence(target), ensure_ascii=False),
                    },
                ],
            }
            response = client.post(f"{options.base_url.rstrip('/')}/chat/completions", json=body)
            try:
                response.raise_for_status()
                payload = response.json()
            finally:
                response.close()
            if not isinstance(payload, dict):
                raise TypeError("OpenRouter returned an invalid response")
            additions = _parse(payload, target, options.model)
            unique = {item.external_id: item for item in (*target.findings, *additions)}
            reviewed.append(replace(target, findings=tuple(unique.values())))
    return replace(run, targets=tuple(reviewed))


__all__ = ["ReviewOptions", "default_prompt_path", "load_prompt", "review_run"]

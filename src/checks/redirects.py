"""Redirect-chain findings over sanitized, policy-revalidated HTTP evidence."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..http import HttpResponseEvidence
from ..models import Finding
from .registry import RULES, CheckContext


def check_redirects(responses: tuple[HttpResponseEvidence, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for index, response in enumerate(responses, start=1):
        context = CheckContext(response)
        destination = response.redirect_url
        if destination is not None:
            findings.append(
                RULES["WEB-TRANSPORT-REDIRECT"].finding(
                    context,
                    f"Redirect hop {index} to {destination}",
                )
            )
            source_parts = urlsplit(response.url)
            destination_parts = urlsplit(destination)
            if source_parts.hostname != destination_parts.hostname:
                findings.append(
                    RULES["WEB-TRANSPORT-CROSS-HOST-REDIRECT"].finding(
                        context,
                        f"Redirect hop {index} crosses to {destination}",
                    )
                )
            if source_parts.scheme == "https" and destination_parts.scheme == "http":
                findings.append(
                    RULES["WEB-TRANSPORT-HTTPS-DOWNGRADE"].finding(
                        context,
                        f"Redirect hop {index} downgrades HTTPS to HTTP",
                    )
                )
        if response.blocked_redirect_reason is not None:
            findings.append(
                RULES["WEB-TRANSPORT-REDIRECT-BLOCKED"].finding(
                    context,
                    f"Redirect hop {index} blocked: {response.blocked_redirect_reason}",
                )
            )
    return tuple(findings)


__all__ = ["check_redirects"]

"""Explicit passive checks over already-collected HTTP evidence."""

from ..models import CheckExecution, Finding
from .content import check_content
from .cookies import check_cookies
from .cors import check_cors
from .headers import check_headers
from .registry import RULES, Check, CheckContext

PASSIVE_CHECKS: tuple[Check, ...] = (check_headers, check_cookies, check_cors, check_content)


def evaluate_passive(
    context: CheckContext,
) -> tuple[tuple[Finding, ...], tuple[CheckExecution, ...]]:
    """Record applicability per rule; truncated/uncollected evidence is never negative."""
    findings = tuple(finding for check in PASSIVE_CHECKS for finding in check(context))
    by_rule = {finding.rule_id: finding for finding in findings}
    executions = []
    html_headers = ("CSP-", "FRAMING-", "REFERRER-", "PERMISSIONS-", "COOP-", "COEP-", "CORP-")
    for rule in RULES:
        if not rule.startswith(("WEB-HEADER-", "WEB-COOKIE-", "WEB-CORS-", "WEB-CONTENT-")):
            continue
        finding = by_rule.get(rule)
        state, reason = "executed-negative", ""
        if rule.startswith("WEB-HEADER-HSTS") and not context.response.url.startswith("https:"):
            state, reason = "unsupported", "HSTS requires HTTPS"
        elif (
            rule.startswith(tuple("WEB-HEADER-" + suffix for suffix in html_headers))
            and not context.is_html
        ):
            state, reason = "unsupported", "Rule requires HTML"
        elif rule.startswith("WEB-COOKIE-") and not context.header_values("set-cookie"):
            state, reason = "skipped", "No cookie attributes observed"
        elif rule.startswith("WEB-CONTENT-SECURITY-TXT") and context.security_txt is None:
            state, reason = "skipped", "security.txt not collected in this page context"
        elif (
            rule
            in {
                "WEB-CONTENT-DIRECTORY-LISTING",
                "WEB-CONTENT-INSECURE-FORM",
                "WEB-CONTENT-MIXED-ACTIVE",
            }
            and not context.is_html
        ):
            state, reason = "unsupported", "Rule requires HTML"
        elif rule.startswith("WEB-CONTENT-") and context.response.truncated:
            state, reason = "exhausted", "Body limit reached"
        if finding:
            state, reason = "executed-positive", ""
        executions.append(
            CheckExecution(
                rule, context.response.url, state, finding.evidence_ids if finding else (), reason
            )
        )
    return findings, tuple(executions)


__all__ = ["PASSIVE_CHECKS", "Check", "CheckContext"]

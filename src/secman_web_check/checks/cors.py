"""Current response CORS policy only; reflection needs separate active probes."""

from ..models import Finding
from .registry import RULES, CheckContext


def check_cors(context: CheckContext) -> tuple[Finding, ...]:
    origins = context.header_values("access-control-allow-origin")
    if not any(origin.strip() == "*" for origin in origins):
        return ()
    findings = [
        RULES["WEB-CORS-WILDCARD"].finding(context, "Access-Control-Allow-Origin: wildcard")
    ]
    if any(
        value.strip() == "true"
        for value in context.header_values("access-control-allow-credentials")
    ):
        findings.append(
            RULES["WEB-CORS-WILDCARD-CREDENTIALS"].finding(
                context,
                "Access-Control-Allow-Origin: wildcard; Access-Control-Allow-Credentials: true",
            )
        )
    return tuple(findings)

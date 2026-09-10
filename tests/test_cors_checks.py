import pytest

from secman_web_check.checks import CheckContext
from secman_web_check.checks.cors import check_cors
from secman_web_check.http import HttpRequest, HttpResponseEvidence
from secman_web_check.models import Severity


def context(headers, origin=None):
    request = HttpRequest(
        "GET", "https://example.com/", () if origin is None else (("Origin", origin),)
    )
    return CheckContext(HttpResponseEvidence(request, 200, headers, b"", False, 0.1))


@pytest.mark.parametrize(
    ("headers", "rule"),
    [
        ((("Access-Control-Allow-Origin", "*"),), "WEB-CORS-WILDCARD"),
        (
            (("access-control-allow-origin", "*"), ("Access-Control-Allow-Credentials", "true")),
            "WEB-CORS-WILDCARD-CREDENTIALS",
        ),
    ],
)
def test_cors_current_response_policy(headers, rule):
    assert rule in {f.rule_id for f in check_cors(context(headers))}


def test_wildcard_with_credentials_is_not_claimed_as_working_credential_exfiltration():
    findings = check_cors(
        context(
            (("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true"))
        )
    )
    finding = next(f for f in findings if f.rule_id == "WEB-CORS-WILDCARD-CREDENTIALS")
    assert finding.severity == Severity.LOW
    assert "browser" in finding.description.lower()


def test_single_observed_matching_origin_is_not_proof_of_reflection():
    assert (
        check_cors(
            context(
                (
                    ("Access-Control-Allow-Origin", "https://allowed.example"),
                    ("Access-Control-Allow-Credentials", "true"),
                ),
                origin="https://allowed.example",
            )
        )
        == ()
    )
    assert check_cors(context(())) == ()


def test_duplicate_cors_headers_remain_visible():
    findings = check_cors(
        context(
            (
                ("Access-Control-Allow-Origin", "https://example.com"),
                ("ACCESS-CONTROL-ALLOW-ORIGIN", "*"),
            )
        )
    )
    assert "WEB-CORS-WILDCARD" in {f.rule_id for f in findings}

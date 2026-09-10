from dataclasses import FrozenInstanceError, replace

import pytest

from secman_web_check.checks import PASSIVE_CHECKS, CheckContext
from secman_web_check.checks.headers import check_headers
from secman_web_check.checks.registry import RULES
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def context(headers=(), *, url="https://example.com/", content_type="text/html"):
    return CheckContext(
        HttpResponseEvidence(
            HttpRequest("GET", url),
            200,
            (("Content-Type", content_type), *headers),
            b"",
            False,
            0.1,
        )
    )


@pytest.mark.parametrize(
    ("headers", "rule"),
    [
        ((), "WEB-HEADER-HSTS-MISSING"),
        ((("Strict-Transport-Security", "max-age=60"),), "WEB-HEADER-HSTS-WEAK"),
        ((("Strict-Transport-Security", "max-age=oops"),), "WEB-HEADER-HSTS-WEAK"),
        ((), "WEB-HEADER-CSP-MISSING"),
        (
            (("Content-Security-Policy-Report-Only", "default-src 'none'"),),
            "WEB-HEADER-CSP-MISSING",
        ),
        ((("Content-Security-Policy", "default-src * 'unsafe-inline'"),), "WEB-HEADER-CSP-UNSAFE"),
        ((), "WEB-HEADER-NOSNIFF-MISSING"),
        ((), "WEB-HEADER-FRAMING-MISSING"),
        ((("X-Frame-Options", "ALLOW-FROM https://example.com"),), "WEB-HEADER-FRAMING-MISSING"),
        ((), "WEB-HEADER-REFERRER-POLICY-MISSING"),
        ((("Referrer-Policy", "unsafe-url"),), "WEB-HEADER-REFERRER-POLICY-WEAK"),
        ((), "WEB-HEADER-PERMISSIONS-POLICY-MISSING"),
        ((), "WEB-HEADER-COOP-MISSING"),
        ((), "WEB-HEADER-COEP-MISSING"),
        ((), "WEB-HEADER-CORP-MISSING"),
        ((("Set-Cookie", "session=secret"),), "WEB-HEADER-CACHE-SENSITIVE"),
        ((("Server", "nginx/1.2"),), "WEB-HEADER-DISCLOSURE"),
        ((("X-Powered-By", "PHP"),), "WEB-HEADER-DISCLOSURE"),
    ],
)
def test_header_rules(headers, rule):
    assert rule in {finding.rule_id for finding in check_headers(context(headers))}


def test_restrictive_headers_avoid_findings():
    headers = (
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=(), microphone=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Set-Cookie", "session=secret"),
        ("Cache-Control", "no-store"),
    )
    assert check_headers(context(headers)) == ()


def test_document_headers_do_not_flag_json_and_hsts_does_not_flag_http():
    findings = check_headers(context(url="http://example.com/", content_type="application/json"))
    assert {f.rule_id for f in findings} == {"WEB-HEADER-NOSNIFF-MISSING"}


def test_duplicate_headers_preserve_effective_hsts_and_intersect_csp():
    ctx = context(
        (
            ("strict-transport-security", "max-age=0"),
            ("STRICT-TRANSPORT-SECURITY", "max-age=31536000"),
            ("Content-Security-Policy", "script-src * 'unsafe-inline'"),
            ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
        )
    )
    rules = {f.rule_id for f in check_headers(ctx)}
    assert "WEB-HEADER-HSTS-WEAK" in rules
    assert "WEB-HEADER-CSP-UNSAFE" not in rules
    assert "WEB-HEADER-FRAMING-MISSING" not in rules


def test_nonce_disables_unsafe_inline_and_first_csp_directive_wins():
    ctx = context(
        (("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline'; script-src *"),)
    )
    assert "WEB-HEADER-CSP-UNSAFE" not in {f.rule_id for f in check_headers(ctx)}


@pytest.mark.parametrize(
    "policy",
    [
        "max-age=" + "9" * 5000,
        "max-age=" + "0" * 5000 + "31536000",
    ],
    ids=["huge-age", "leading-zeros"],
)
def test_extremely_long_hsts_integer_does_not_crash_or_flag_valid_long_lifetime(policy):
    ctx = context((("Strict-Transport-Security", policy),))
    assert "WEB-HEADER-HSTS-WEAK" not in {f.rule_id for f in check_headers(ctx)}


@pytest.mark.parametrize(
    "policy",
    [
        'max-age="31536000',
        'max-age=31536000"',
        "max-age=31536000; max-age=bad",
        "max-age=31536000; max-age=0",
    ],
)
def test_malformed_or_duplicate_hsts_max_age_is_weak(policy):
    ctx = context((("Strict-Transport-Security", policy),))
    assert "WEB-HEADER-HSTS-WEAK" in {f.rule_id for f in check_headers(ctx)}


def test_script_src_elem_can_override_restrictive_default_and_script_policy():
    ctx = context(
        (("Content-Security-Policy", "default-src 'none'; script-src 'none'; script-src-elem *"),)
    )
    assert "WEB-HEADER-CSP-UNSAFE" in {f.rule_id for f in check_headers(ctx)}


def test_metadata_is_immutable_and_evidence_bounded_without_header_values():
    ctx = context((("Server", "secret/" + "sensitive" * 1000),))
    findings = tuple(f for check in PASSIVE_CHECKS for f in check(ctx))
    assert findings
    assert all(f.description and f.recommendation for f in findings)
    assert all(len(f.evidence) <= 512 and "sensitive" not in f.evidence for f in findings)
    with pytest.raises(FrozenInstanceError):
        RULES[findings[0].rule_id].title = "changed"
    with pytest.raises(TypeError):
        RULES["new"] = replace(RULES[findings[0].rule_id], rule_id="new")

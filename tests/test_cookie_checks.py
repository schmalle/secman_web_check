import pytest

from secman_web_check.checks import CheckContext
from secman_web_check.checks.cookies import check_cookies
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def context(*cookies, url="https://app.example.com/"):
    return CheckContext(
        HttpResponseEvidence(
            HttpRequest("GET", url), 200, tuple(("Set-Cookie", c) for c in cookies), b"", False, 0.1
        )
    )


@pytest.mark.parametrize(
    ("cookie", "rule"),
    [
        ("session=value; HttpOnly; SameSite=Lax", "WEB-COOKIE-SECURE-MISSING"),
        ("session=value; Secure; SameSite=Lax", "WEB-COOKIE-HTTPONLY-MISSING"),
        ("session=value; Secure; HttpOnly", "WEB-COOKIE-SAMESITE-MISSING"),
        ("session=value; Secure; HttpOnly; SameSite=bad", "WEB-COOKIE-SAMESITE-MISSING"),
        ("session=value; HttpOnly; SameSite=None", "WEB-COOKIE-SAMESITE-NONE-INSECURE"),
        ("__Secure-session=value; HttpOnly; SameSite=Lax", "WEB-COOKIE-PREFIX-INVALID"),
        (
            "__Host-session=value; Secure; HttpOnly; SameSite=Lax; Domain=app.example.com; Path=/",
            "WEB-COOKIE-PREFIX-INVALID",
        ),
        (
            "__Host-session=value; Secure; HttpOnly; SameSite=Lax; Path=/admin",
            "WEB-COOKIE-PREFIX-INVALID",
        ),
        (
            "session=value; Secure; HttpOnly; SameSite=Lax; Domain=.example.com",
            "WEB-COOKIE-DOMAIN-BROAD",
        ),
    ],
)
def test_cookie_rules(cookie, rule):
    assert rule in {f.rule_id for f in check_cookies(context(cookie))}


def test_cookie_evidence_never_contains_values_or_untrusted_cookie_names():
    findings = check_cookies(context("session=top-secret; Path=/", "token-secret=value-secret"))
    assert findings
    assert all("secret" not in f.evidence and len(f.evidence) <= 512 for f in findings)
    assert all("Set-Cookie" in f.evidence for f in findings)


def test_duplicate_cookie_headers_are_checked_independently_and_rules_are_aggregated():
    findings = check_cookies(
        context(
            "first=a; Secure; HttpOnly; SameSite=Lax",
            "second=b; Expires=Wed, 21 Oct 2030 07:28:00 GMT; HttpOnly; SameSite=Lax",
            "third=c; HttpOnly; SameSite=Lax",
        )
    )
    assert [f.rule_id for f in findings] == ["WEB-COOKIE-SECURE-MISSING"]
    assert "#2" in findings[0].evidence and "#3" in findings[0].evidence


def test_secure_cookie_and_non_cookie_header_have_no_findings():
    assert (
        check_cookies(context("__Host-session=x; sEcUrE; HttpOnly; SameSite=Strict; Path=/")) == ()
    )
    assert check_cookies(context("malformed")) == ()
    assert check_cookies(context()) == ()


def test_secure_prefix_cannot_be_set_over_http():
    findings = check_cookies(
        context(
            "__Secure-session=x; Secure; HttpOnly; SameSite=Strict", url="http://app.example.com/"
        )
    )
    assert "WEB-COOKIE-PREFIX-INVALID" in {f.rule_id for f in findings}

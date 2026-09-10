from dataclasses import replace
from datetime import UTC, datetime

import pytest

from secman_web_check.checks import CheckContext
from secman_web_check.checks.content import check_content
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def response(body=b"", *, url="https://example.com/", status=200, content_type="text/html"):
    return HttpResponseEvidence(
        HttpRequest("GET", url), status, (("Content-Type", content_type),), body, False, 0.1
    )


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        (
            b'<title>Index of /files</title><h1>Index of /files</h1><a href="../">Parent Directory</a>',
            "WEB-CONTENT-DIRECTORY-LISTING",
        ),
        (
            b'Traceback (most recent call last):\n  File "/app/view.py", line 20\nValueError: secret',
            "WEB-CONTENT-DEBUG-ERROR",
        ),
        (
            b"<pre>java.lang.NullPointerException\n at com.example.App.run(App.java:20)</pre>",
            "WEB-CONTENT-DEBUG-ERROR",
        ),
        (b"<p>upstream: http://10.20.30.40/service</p>", "WEB-CONTENT-INTERNAL-ADDRESS"),
        (
            b'<form action="http://example.com/login"><input type="password"></form>',
            "WEB-CONTENT-INSECURE-FORM",
        ),
        (b'<script src="http://cdn.example.com/app.js"></script>', "WEB-CONTENT-MIXED-ACTIVE"),
        (
            b'<link rel="stylesheet" href="http://cdn.example.com/style.css">',
            "WEB-CONTENT-MIXED-ACTIVE",
        ),
        (
            b"-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----",
            "WEB-CONTENT-SECRET",
        ),
    ],
)
def test_content_rules(body, rule):
    findings = check_content(CheckContext(response(body)))
    assert rule in {f.rule_id for f in findings}
    assert all(f.confidence < 1.0 for f in findings)
    assert all("secret" not in f.evidence and len(f.evidence) <= 512 for f in findings)


@pytest.mark.parametrize(
    "body",
    [
        b"<h1>Index of topics</h1>",
        b"This documentation explains Traceback (most recent call last) errors.",
        b"Version 10.20.30.40",
        b'<form action="/login"><input type="password"></form>',
        b'<img src="http://cdn.example.com/image.png">',
        b'<script src="//cdn.example.com/app.js"></script>',
        b"-----BEGIN PRIVATE KEY----- is a PEM label.",
    ],
)
def test_content_avoids_single_indicator_and_safe_transport_false_positives(body):
    assert check_content(CheckContext(response(body))) == ()


def test_http_password_form_and_html_base_are_considered():
    findings = check_content(
        CheckContext(response(b'<form><input type="password"></form>', url="http://example.com/"))
    )
    assert "WEB-CONTENT-INSECURE-FORM" in {f.rule_id for f in findings}
    findings = check_content(
        CheckContext(response(b'<base href="http://example.com/"><script src="/app.js"></script>'))
    )
    assert "WEB-CONTENT-MIXED-ACTIVE" in {f.rule_id for f in findings}


def test_json_is_not_parsed_as_html():
    assert (
        check_content(
            CheckContext(
                response(
                    b'{"example": "<script src="http://example.com/x.js"></script>"}',
                    content_type="application/json",
                )
            )
        )
        == ()
    )


def test_downgrade_detected_even_when_collector_blocked_it():
    hop = replace(
        response(status=302),
        redirect_url="http://example.com/",
        blocked_redirect_reason="HTTPS downgrade",
    )
    assert "WEB-TRANSPORT-HTTPS-DOWNGRADE" in {f.rule_id for f in check_content(CheckContext(hop))}


def test_internal_address_in_location_header_is_detected_without_disclosing_it():
    hop = replace(response(status=302), headers=(("Location", "https://192.168.12.34/private"),))
    findings = check_content(CheckContext(hop))
    assert "WEB-CONTENT-INTERNAL-ADDRESS" in {f.rule_id for f in findings}
    assert all("192.168" not in f.evidence and "/private" not in f.evidence for f in findings)


def test_form_submit_button_can_override_secure_form_action():
    findings = check_content(
        CheckContext(
            response(
                b'<form action="https://example.com/login"><input type="password">'
                b'<button formaction="http://example.com/submit">Send</button></form>'
            )
        )
    )
    assert "WEB-CONTENT-INSECURE-FORM" in {f.rule_id for f in findings}


@pytest.mark.parametrize(
    ("status", "body", "rule"),
    [
        (404, b"", "WEB-CONTENT-SECURITY-TXT-MISSING"),
        (200, b"Contact: mailto:security@example.com\n", "WEB-CONTENT-SECURITY-TXT-INVALID"),
        (
            200,
            b"Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00Z\n",
            "WEB-CONTENT-SECURITY-TXT-EXPIRED",
        ),
        (200, b"Contact: secret\nExpires: later\n", "WEB-CONTENT-SECURITY-TXT-INVALID"),
        (
            200,
            b"Contact: mailto:security@example.com\nExpires: 2027-01-01 00:00:00+00:00\n",
            "WEB-CONTENT-SECURITY-TXT-INVALID",
        ),
    ],
)
def test_optional_security_txt_evidence(status, body, rule):
    ctx = CheckContext(
        response(),
        security_txt=response(body, status=status, content_type="text/plain"),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert rule in {f.rule_id for f in check_content(ctx)}


def test_security_txt_not_collected_is_not_reported_missing():
    assert check_content(CheckContext(response())) == ()
    ctx = CheckContext(
        response(),
        security_txt=response(
            b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
            content_type="text/plain",
        ),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert check_content(ctx) == ()

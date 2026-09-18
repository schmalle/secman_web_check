from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest

from secman_web_check.models import Finding, Severity, TargetResult, TargetStatus
from secman_web_check.secman import (
    AmbiguousSubject,
    IntegrationClient,
    IntegrationSubject,
    SecmanIntegrationError,
    build_run_body,
    match_subject,
    validate_base_url,
)
from secman_web_check.targets import normalize_target


def _result() -> TargetResult:
    started = datetime(2026, 9, 11, 10, 0, tzinfo=UTC)
    finding = Finding.create(
        "WEB-HSTS-001",
        "https://example.com/",
        Severity.HIGH,
        "Missing HSTS",
        description="The response omits Strict-Transport-Security.",
        recommendation="Add a suitable HSTS header.",
        evidence="Header absent.",
        created_at=started,
    )
    return TargetResult(
        target=normalize_target("https://example.com/"),
        status=TargetStatus.SUCCESS,
        findings=(finding,),
        started_at=started,
        completed_at=datetime(2026, 9, 11, 10, 1, tzinfo=UTC),
    )


def test_build_run_body_uses_the_shared_v1_contract() -> None:
    subject = IntegrationSubject(2, 1, 3, "example.com", "https://example.com/")

    body = build_run_body(1, subject, _result(), metadata={"targetCount": 1})

    assert body["scannerId"] == 1
    assert body["subjectId"] == 2
    assert body["completeCoverage"] is True
    assert body["findings"][0]["externalId"].startswith("WEB-HSTS-001:")
    assert body["findings"][0]["severity"] == "HIGH"
    assert body["runKey"].startswith("secman-web-check-v1:")


def test_run_key_is_deterministic_and_complete_coverage_tracks_the_result() -> None:
    subject = IntegrationSubject(2, 1, 3, "example.com", "https://example.com/")
    result = replace(_result(), complete=False)

    first = build_run_body(1, subject, result, metadata={"targetCount": 1, "active": False})
    reordered = build_run_body(
        1,
        subject,
        result,
        metadata={"active": False, "targetCount": 1},
    )

    assert first["completeCoverage"] is False
    assert first["runKey"] == reordered["runKey"]


def test_match_subject_accepts_canonical_uri_or_host() -> None:
    uri = IntegrationSubject(1, 4, 8, "other", "https://example.com/")
    host = IntegrationSubject(2, 4, 9, "example.com", None)

    assert match_subject([uri], "https://example.com/") == uri
    assert match_subject([host], "https://example.com/path") == host


def test_match_subject_rejects_ambiguous_hostname() -> None:
    subjects = [
        IntegrationSubject(1, 4, 8, "example.com", "https://example.com/a"),
        IntegrationSubject(2, 4, 9, "example.com", "https://example.com/b"),
    ]
    with pytest.raises(AmbiguousSubject):
        match_subject(subjects, "https://example.com/")


def test_match_subject_uses_aws_account_before_uri_or_hostname() -> None:
    first = IntegrationSubject(1, 4, 8, "example.com", "https://example.com/", "111122223333")
    second = IntegrationSubject(2, 4, 9, "example.com", "https://example.com/", "444455556666")

    assert (
        match_subject(
            [first, second],
            "https://example.com/",
            aws_account_number="444455556666",
        )
        == second
    )
    assert (
        match_subject(
            [first, second],
            "https://example.com/",
            aws_account_number="999900001111",
        )
        is None
    )


def test_client_uses_bearer_auth_without_following_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "content": [
                        {
                            "id": 2,
                            "scannerId": 1,
                            "assetId": 3,
                            "name": "example.com",
                            "uri": "https://example.com/",
                            "cloudAccountId": "111122223333",
                        }
                    ],
                    "totalPages": 1,
                },
            )
        return httpx.Response(201, json={"id": 7, "replayed": False})

    client = IntegrationClient("https://secman.example", "secret-token")
    client._client = httpx.Client(  # type: ignore[reportPrivateUsage]
        base_url="https://secman.example",
        headers={"Authorization": "Bearer secret-token"},
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    with client:
        subjects = client.list_subjects(1)
        response = client.submit_run({"scannerId": 1})

    assert subjects[0].name == "example.com"
    assert subjects[0].cloud_account_id == "111122223333"
    assert response["id"] == 7
    assert all(request.headers["Authorization"] == "Bearer secret-token" for request in requests)
    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", "/api/integrations/v1/scanners/1/subjects"),
        ("POST", "/api/integrations/v1/runs"),
    ]


def test_client_errors_do_not_include_response_bodies_or_credentials() -> None:
    sensitive = "internal-error-detail"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text=sensitive)

    client = IntegrationClient("https://secman.example", "secret-token")
    client._client = httpx.Client(  # type: ignore[reportPrivateUsage]
        base_url="https://secman.example",
        headers={"Authorization": "Bearer secret-token"},
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    with client:
        with pytest.raises(SecmanIntegrationError) as discovery:
            client.list_subjects(1)
        with pytest.raises(SecmanIntegrationError) as submission:
            client.submit_run({"scannerId": 1})

    for error in (discovery.value, submission.value):
        assert sensitive not in str(error)
        assert "secret-token" not in str(error)


def test_base_url_rejects_non_https_and_credentials() -> None:
    for value in ("http://secman.example", "https://user:pass@secman.example"):
        try:
            validate_base_url(value)
        except SecmanIntegrationError:
            pass
        else:
            raise AssertionError(f"accepted unsafe SecMan URL: {value}")

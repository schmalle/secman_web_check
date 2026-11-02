from datetime import UTC, datetime, timedelta, timezone

from secman_web_check.models import Finding, Severity


def test_finding_identity_ignores_mutable_title_and_severity() -> None:
    first = Finding.create("WEB-HSTS-001", "https://example.com/", Severity.HIGH, "Missing HSTS")
    changed = Finding.create("WEB-HSTS-001", "https://example.com/", Severity.LOW, "New title")

    assert first.external_id == changed.external_id


def test_finding_create_normalizes_an_aware_timestamp_to_utc() -> None:
    finding = Finding.create(
        "WEB-HSTS-001",
        "https://example.com/",
        Severity.HIGH,
        "Missing HSTS",
        created_at=datetime(2026, 9, 9, 14, 0, tzinfo=timezone(timedelta(hours=2))),
    )

    assert finding.created_at == datetime(2026, 9, 9, 12, 0, tzinfo=UTC)


def test_finding_identity_and_url_do_not_retain_query_values() -> None:
    first = Finding.create(
        "WEB-TEST", "https://example.com/path?token=secret-one", Severity.LOW, "test"
    )
    second = Finding.create(
        "WEB-TEST", "https://example.com/path?token=secret-two", Severity.LOW, "test"
    )

    assert first.url == "https://example.com/path"
    assert first.external_id == second.external_id

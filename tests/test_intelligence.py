import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from secman_web_check.intelligence import _affected, _normalize, load_snapshot, update_snapshot
from secman_web_check.models import ComponentCategory, DetectedComponent


def record(*, withdrawn=False):
    return {
        "id": "GHSA-fixture-safe",
        "modified": "2026-10-20T00:00:00Z",
        "withdrawn": "2026-10-20T00:00:00Z" if withdrawn else None,
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "jquery"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "3.5.0"}]}
                ],
            }
        ],
    }


def snapshot(tmp_path, *, age=0, withdrawn=False):
    path = tmp_path / "advisories.json"
    payload = {
        "version": 1,
        "fetchedAt": (datetime.now(UTC) - timedelta(days=age)).isoformat(),
        "advisories": [_normalize(record(withdrawn=withdrawn))],
    }
    raw = json.dumps(payload).encode()
    path.write_bytes(raw)
    return path, sha256(raw).hexdigest()


def component(version):
    return DetectedComponent.create(
        ComponentCategory.JAVASCRIPT_LIBRARY,
        "jQuery",
        version=version,
        confidence=0.95,
        evidence_type="fixture",
        evidence="Synthetic component fingerprint",
    )


def test_verified_snapshot_matches_boundaries_and_reports_provenance(tmp_path):
    database = load_snapshot(*snapshot(tmp_path))
    assert database.findings((component("3.4.1"),), "https://example.com")
    assert not database.findings(
        (component("3.5.0"), component(None), component("unknown")), "https://example.com"
    )
    assert database.provenance()["sources"] == ["https://api.osv.dev/v1/vulns/GHSA-fixture-safe"]
    assert not database.stale
    assert load_snapshot(*snapshot(tmp_path, age=31)).stale
    assert not load_snapshot(*snapshot(tmp_path, withdrawn=True)).findings(
        (component("3.4.1"),), "https://example.com"
    )


def test_snapshot_tampering_and_invalid_provenance_are_rejected(tmp_path):
    path, digest = snapshot(tmp_path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        load_snapshot(path, digest)
    document = json.loads(path.read_text())
    document["advisories"][0]["source"] = "https://attacker.example/"
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="provenance"):
        load_snapshot(path, sha256(raw).hexdigest())


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("0.9.0", False),
        ("1.0.0", True),
        ("3.4.9", True),
        ("3.5.0", False),
        ("3.5.0-beta.1", True),
        ("3.5.0+build", False),
    ],
)
def test_semver_range_boundaries_and_prereleases(version, expected):
    assert _affected(version, [{"introduced": "1.0.0"}, {"fixed": "3.5.0"}]) is expected


def test_disjoint_ranges_last_affected_and_limit():
    events = [
        {"introduced": "0"},
        {"fixed": "1.0.0"},
        {"introduced": "2.0.0"},
        {"last_affected": "2.5.0"},
    ]
    assert _affected("0.9.0", events)
    assert not _affected("1.0.0", events)
    assert _affected("2.5.0", events)
    assert not _affected("2.5.1", events)
    assert not _affected("3.0.0", [{"introduced": "0"}, {"limit": "3.0.0"}])


def test_explicit_update_does_not_send_asset_inventory_or_persist_raw_advisory_body(
    monkeypatch, tmp_path
):
    from secman_web_check.http import HttpRequest, HttpResponseEvidence

    requests = []

    def collect(_self, target):
        requests.append(target.url)
        payload = {**record(), "details": "SYNTHETIC_RAW_BODY"}
        return (
            HttpResponseEvidence(
                HttpRequest("GET", target.url), 200, (), json.dumps(payload).encode(), False, 0.0
            ),
        )

    monkeypatch.setattr("secman_web_check.intelligence.HttpCollector.collect", collect)
    path = tmp_path / "normalized.json"
    digest = update_snapshot(("GHSA-fixture-safe",), path)
    assert requests == ["https://api.osv.dev/v1/vulns/GHSA-fixture-safe"]
    assert "SYNTHETIC_RAW_BODY" not in path.read_text()
    assert load_snapshot(path, digest).findings((component("3.4.1"),), "https://example.com")


def test_package_update_discovers_new_records_with_bounded_pagination(monkeypatch):
    from secman_web_check.intelligence import _package_records

    calls = []
    documents = [
        {"vulns": [record()], "next_page_token": "page-2"},
        {"vulns": [{**record(), "id": "GHSA-new-advisory"}]},
    ]

    class Response:
        def __init__(self, document):
            self.document = document

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def raise_for_status(self):
            pass

        def iter_bytes(self, chunk_size):
            yield json.dumps(self.document).encode()

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def stream(self, method, url, json):
            calls.append((method, url, json))
            return Response(documents.pop(0))

    monkeypatch.setattr("secman_web_check.intelligence.httpx.Client", Client)
    monkeypatch.setattr(
        "secman_web_check.intelligence.resolve_allowed", lambda *_args: ("1.1.1.1",)
    )
    monkeypatch.setattr(
        "secman_web_check.intelligence.pinned_transport", lambda *_args, **_kwargs: object()
    )
    records = _package_records("jquery")
    assert {item["id"] for item in records} == {"GHSA-fixture-safe", "GHSA-new-advisory"}
    assert calls[0][2] == {"package": {"name": "jquery", "ecosystem": "npm"}}
    assert calls[1][2]["page_token"] == "page-2"
    assert all(url == "https://api.osv.dev/v1/query" for _, url, _ in calls)


def test_unselected_ecosystems_are_explicitly_excluded_not_unsupported_npm_ranges():
    payload = record()
    payload["affected"].append(
        {
            "package": {"ecosystem": "Maven", "name": "org.example:jquery"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        }
    )
    normalized = _normalize(payload)
    assert normalized["unsupported"] == 0
    assert normalized["excludedPackages"] == 1
    assert [item["package"] for item in normalized["affected"]] == ["jquery"]

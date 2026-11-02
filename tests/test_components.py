from secman_web_check.components import (
    detect_components,
    find_component_vulnerabilities,
    inventory_response_is_complete,
    sanitize_inventory_url,
)
from secman_web_check.http import HttpRequest, HttpResponseEvidence


def _response(body: bytes, headers=(), *, status_code=200, truncated=False):
    return HttpResponseEvidence(
        HttpRequest("GET", "https://app.example/path?session=secret"),
        status_code,
        tuple(headers),
        body,
        truncated,
        0.1,
    )


def test_detects_bounded_header_and_resource_signatures_without_query_values():
    response = _response(
        b"""
        <html><head>
          <script src="https://cdn.example/jquery-3.7.1.min.js?token=secret"></script>
          <link rel="stylesheet" href="/css/bootstrap-5.3.3.min.css?key=secret">
        </head></html>
        """,
        (("Content-Type", "text/html; charset=utf-8"), ("Server", "nginx/1.25.4")),
    )

    components = detect_components(response)

    assert [(item.name, item.version) for item in components] == [
        ("Bootstrap", "5.3.3"),
        ("jQuery", "3.7.1"),
        ("nginx", "1.25.4"),
    ]
    assert all("secret" not in repr(item) for item in components)
    assert all("?" not in item.source_url for item in components if item.source_url)


def test_ignores_unknown_resources_and_rejects_credentialed_inventory_urls():
    response = _response(
        b'<script src="/assets/application.js"></script>',
        (("Content-Type", "text/html"), ("Server", "custom-edge")),
    )

    assert detect_components(response) == ()
    assert sanitize_inventory_url("https://user:secret@app.example/") is None
    assert sanitize_inventory_url("https://:secret@app.example/") is None


def test_only_complete_successful_html_can_resolve_absent_components():
    headers = (("Content-Type", "text/html; charset=utf-8"),)

    assert inventory_response_is_complete(_response(b"<html></html>", headers)) is True
    assert (
        inventory_response_is_complete(_response(b"<html></html>", headers, truncated=True))
        is False
    )
    assert (
        inventory_response_is_complete(_response(b"<html></html>", headers, status_code=500))
        is False
    )
    assert (
        inventory_response_is_complete(_response(b"{}", (("Content-Type", "application/json"),)))
        is False
    )


def test_known_component_version_creates_local_advisory_finding():
    components = detect_components(
        _response(
            b'<script src="/jquery-3.4.1.min.js"></script>',
            (("Content-Type", "text/html"),),
        )
    )

    findings = find_component_vulnerabilities(components, "https://app.example/")

    assert {finding.rule_id for finding in findings} == {
        "WEB-COMPONENT-CVE-2020-11022",
        "WEB-COMPONENT-CVE-2020-11023",
    }
    assert all(finding.engine == "secman-web-check-components" for finding in findings)


def test_fixed_or_unknown_component_versions_do_not_claim_vulnerability():
    components = detect_components(
        _response(
            b'<script src="/jquery-3.7.1.min.js"></script><script src="/react.min.js"></script>',
            (("Content-Type", "text/html"),),
        )
    )

    assert find_component_vulnerabilities(components, "https://app.example/") == ()

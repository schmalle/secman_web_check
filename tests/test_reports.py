import csv
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from rich.console import Console

from secman_web_check.models import (
    BrowserHttpObservation,
    BrowserNavigationDiagnostic,
    ComponentCategory,
    DetectedComponent,
    ExposureObservation,
    Finding,
    JavaScriptAsset,
    Reachability,
    ScanRun,
    Severity,
    TargetResult,
    TargetStatus,
)
from secman_web_check.reports import render_terminal, write_csv, write_html, write_json, write_sarif
from secman_web_check.targets import normalize_target


def sample_run():
    target = replace(normalize_target("https://example.com"), aws_account_number="111122223333")
    finding = Finding.create(
        "WEB-TEST",
        target.url,
        Severity.HIGH,
        "<script>alert(1)</script>",
        evidence="<img src=x onerror=alert(1)>",
    )
    now = datetime.now(UTC)
    component = DetectedComponent.create(
        ComponentCategory.JAVASCRIPT_LIBRARY,
        "jQuery",
        version="3.7.1",
        confidence=0.95,
        evidence_type="RESOURCE_URL",
        evidence="Matched jQuery resource URL",
        source_url="https://cdn.example/jquery-3.7.1.min.js",
    )
    result = TargetResult(
        target,
        TargetStatus.SUCCESS,
        (finding,),
        components=(component,),
        javascript_assets=(JavaScriptAsset("https://example.com/app.js", "a" * 64, 1234, 200),),
        exposure=ExposureObservation(
            target.url, target.url, Reachability.REACHABLE, 200, 0, body_length=512
        ),
        inventory_complete=True,
        started_at=now,
        completed_at=now,
    )
    return ScanRun("00000000-0000-4000-8000-000000000001", (result,), now, now)


def test_reports_share_finding_identity_and_html_escapes(tmp_path):
    run = sample_run()
    json_path = write_json(run, tmp_path / "report.json")
    sarif_path = write_sarif(run, tmp_path / "report.sarif.json")
    html_path = write_html(run, tmp_path / "report.html")
    external_id = run.targets[0].findings[0].external_id
    assert external_id in json_path.read_text()
    assert external_id in sarif_path.read_text()
    html = html_path.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "default-src 'none'" in html
    json_report = json.loads(json_path.read_text())
    assert json_report["schemaVersion"] == "1.3"
    assert json_report["targets"][0]["awsAccountNumber"] == "111122223333"
    assert json_report["targets"][0]["components"][0]["name"] == "jQuery"
    assert json_report["targets"][0]["javascriptAssets"][0]["sha256"] == "a" * 64
    assert json_report["targets"][0]["exposure"]["reachability"] == "REACHABLE"
    assert json_report["targets"][0]["exposure"]["bodyLength"] == 512
    assert "512 bytes" in html
    assert "https://example.com/app.js" in html
    assert json.loads(sarif_path.read_text())["version"] == "2.1.0"


def test_terminal_report_renders_without_raw_response_body():
    console = Console(record=True, width=120)
    render_terminal(sample_run(), console)
    output = console.export_text()
    assert "WEB-TEST" in output
    assert "jQuery" in output
    assert "REACHABLE" in output
    assert "512 bytes" in output
    assert "https://example.com/app.js" in output


@pytest.mark.parametrize(
    ("http_status", "redirect_count", "flag", "label"),
    [(200, 2, True, "Yes"), (302, 0, False, "No"), (None, 0, None, "Unknown")],
)
def test_reports_flag_followed_http_redirects(tmp_path, http_status, redirect_count, flag, label):
    run = sample_run()
    target = run.targets[0]
    exposure = replace(target.exposure, http_status=http_status, redirect_count=redirect_count)
    run = replace(
        run, targets=(replace(target, exposure=exposure, browser_navigation_observed=flag),)
    )

    report = json.loads(write_json(run, tmp_path / "report.json").read_text())
    sarif = json.loads(write_sarif(run, tmp_path / "report.sarif.json").read_text())
    html = write_html(run, tmp_path / "report.html").read_text()
    csv_report = write_csv(run, tmp_path / "report.csv").read_text()
    console = Console(record=True)
    render_terminal(run, console)

    assert report["targets"][0]["exposure"]["redirectFollowed"] is flag
    assert report["targets"][0]["browserNavigationObserved"] is flag
    assert sarif["runs"][0]["properties"]["targets"][0]["exposure"]["redirectFollowed"] is flag
    assert f"HTTP redirect followed: <strong>{label}</strong>" in html
    browser_label = "Not checked" if flag is None else label
    assert f"Browser navigation after load: <strong>{browser_label}</strong>" in html
    assert next(csv.DictReader(csv_report.splitlines()))["redirect_followed"] == label
    assert next(csv.DictReader(csv_report.splitlines()))["browser_navigation_observed"] == label
    assert f"HTTP redirect followed: {label}" in console.export_text()


def test_reports_record_blocked_browser_navigation(tmp_path):
    run = sample_run()
    diagnostic = BrowserNavigationDiagnostic("blocked-origin", "login.microsoftonline.com")
    run = replace(
        run,
        targets=(
            replace(
                run.targets[0],
                browser_navigation_diagnostic=diagnostic,
                browser_navigation_hops=("auth.example", "login.microsoftonline.com"),
                browser_http=BrowserHttpObservation(302, "auth.example"),
            ),
        ),
    )
    report = json.loads(write_json(run, tmp_path / "report.json").read_text())
    sarif = json.loads(write_sarif(run, tmp_path / "report.sarif.json").read_text())
    html = write_html(run, tmp_path / "report.html").read_text()
    rows = csv.DictReader(write_csv(run, tmp_path / "report.csv").read_text().splitlines())

    expected = {"reason": "blocked-origin", "hostname": "login.microsoftonline.com"}
    assert report["targets"][0]["browserNavigationDiagnostic"] == expected
    assert sarif["runs"][0]["properties"]["targets"][0]["browserNavigationDiagnostic"] == expected
    assert "Attempted → login.microsoftonline.com · blocked by scanner policy" in html
    assert "HTTP 302 → auth.example" in html
    assert report["targets"][0]["browserHttp"] == {
        "statusCode": 302,
        "redirectHostname": "auth.example",
    }
    assert report["targets"][0]["browserNavigationHops"] == [
        "auth.example",
        "login.microsoftonline.com",
    ]
    row = next(rows)
    assert row["browser_navigation_reason"] == expected["reason"]
    assert row["browser_navigation_hostname"] == expected["hostname"]
    assert row["browser_http"] == "HTTP 302 → auth.example"

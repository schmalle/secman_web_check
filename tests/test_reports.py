import json
from dataclasses import replace
from datetime import UTC, datetime

from rich.console import Console

from secman_web_check.models import (
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
from secman_web_check.reports import render_terminal, write_html, write_json, write_sarif
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
    assert json_report["schemaVersion"] == "1.2"
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

import json
from dataclasses import replace
from datetime import UTC, datetime

from rich.console import Console

from secman_web_check.models import Finding, ScanRun, Severity, TargetResult, TargetStatus
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
    result = TargetResult(
        target, TargetStatus.SUCCESS, (finding,), started_at=now, completed_at=now
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
    assert json_report["schemaVersion"] == "1.0"
    assert json_report["targets"][0]["awsAccountNumber"] == "111122223333"
    assert json.loads(sarif_path.read_text())["version"] == "2.1.0"


def test_terminal_report_renders_without_raw_response_body():
    console = Console(record=True, width=120)
    render_terminal(sample_run(), console)
    assert "WEB-TEST" in console.export_text()

from datetime import UTC, datetime

from typer.testing import CliRunner

from secman_web_check.cli import app
from secman_web_check.models import ScanRun, TargetResult, TargetStatus

runner = CliRunner()


def clean_run(targets, _config):
    now = datetime.now(UTC)
    return ScanRun(
        "00000000-0000-4000-8000-000000000002",
        tuple(
            TargetResult(target, TargetStatus.SUCCESS, started_at=now, completed_at=now)
            for target in targets
        ),
        now,
        now,
    )


def test_help_documents_safety_and_integration_opt_ins():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in ("--active", "--allow-private-targets", "--store-db", "--push-to-secman"):
        assert option in result.output


def test_scan_rejects_missing_or_conflicting_target_sources(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("example.com\n")
    assert runner.invoke(app, ["scan"]).exit_code == 2
    assert (
        runner.invoke(app, ["scan", "example.com", "--targets-file", str(targets)]).exit_code == 2
    )


def test_single_target_writes_all_reports_without_network(monkeypatch, tmp_path):
    monkeypatch.setattr("secman_web_check.cli.scan_all", clean_run)
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--format",
            "all",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
    )
    assert result.exit_code == 0, result.output
    assert len(list(tmp_path.glob("*.json"))) == 2
    assert len(list(tmp_path.glob("*.html"))) == 1

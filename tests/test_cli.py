from dataclasses import replace
from datetime import UTC, datetime

from typer.testing import CliRunner

from secman_web_check.cli import _push_to_secman, app
from secman_web_check.models import ScanRun, TargetResult, TargetStatus
from secman_web_check.secman import IntegrationSubject
from secman_web_check.targets import normalize_target

runner = CliRunner()


def clean_run(targets, _config, progress=None):
    now = datetime.now(UTC)
    results = tuple(
        TargetResult(target, TargetStatus.SUCCESS, started_at=now, completed_at=now)
        for target in targets
    )
    if progress is not None:
        for completed, result in enumerate(results, 1):
            progress(completed, len(results), result)
    return ScanRun(
        "00000000-0000-4000-8000-000000000002",
        results,
        now,
        now,
    )


def test_help_documents_safety_and_integration_opt_ins():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in (
        "--active",
        "--allow-private-targets",
        "--store-db",
        "--push-to-secman",
        "--strict",
        "--targets-csv",
        "--targets-from-secman",
        "--dirbuster",
        "--external-scanner",
        "--javascript-inventory",
        "--llm-review",
        "--llm-prompt",
    ):
        assert option in result.output


def test_external_scanner_is_explicit_and_validated():
    result = runner.invoke(app, ["scan", "example.com", "--external-scanner", "unknown"])

    assert result.exit_code == 2
    assert "must be nuclei or nikto" in result.output


def test_javascript_inventory_is_forwarded_as_explicit_opt_in(monkeypatch, tmp_path):
    calls = []

    def scan_with_options(targets, config, **kwargs):
        calls.append(kwargs)
        return clean_run(targets, config, progress=kwargs.get("progress"))

    monkeypatch.setattr("secman_web_check.cli.scan_all", scan_with_options)
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--javascript-inventory",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["javascript"] is True


def test_llm_review_requires_key_before_scanning(monkeypatch, tmp_path):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("custom review prompt", encoding="utf-8")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(
        "secman_web_check.cli.scan_all",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("scan ran")),
    )

    result = runner.invoke(
        app,
        ["scan", "example.com", "--llm-review", "--llm-prompt", str(prompt)],
    )

    assert result.exit_code == 2
    assert "OPENROUTER_API_KEY" in result.output


def test_scan_rejects_missing_or_conflicting_target_sources(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("example.com\n")
    targets_csv = tmp_path / "targets.csv"
    targets_csv.write_text("awsAccountNumber,target\n111122223333,example.com\n")
    assert runner.invoke(app, ["scan"]).exit_code == 2
    assert (
        runner.invoke(app, ["scan", "example.com", "--targets-file", str(targets)]).exit_code == 2
    )
    assert (
        runner.invoke(
            app,
            ["scan", "--targets-file", str(targets), "--targets-csv", str(targets_csv)],
        ).exit_code
        == 2
    )
    assert runner.invoke(app, ["scan", "example.com", "--targets-from-secman"]).exit_code == 2


def test_scan_skips_invalid_target_file_lines_without_strict(monkeypatch, tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("example.com\nftp://unsupported.example\n")
    scanned = []
    monkeypatch.setattr(
        "secman_web_check.cli.scan_all",
        lambda targets, config, **kwargs: (
            scanned.append(targets) or clean_run(targets, config, **kwargs)
        ),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--targets-file",
            str(targets_file),
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0, result.output
    assert [target.host for target in scanned[0]] == ["example.com"]
    assert "ftp://unsupported.example" in result.output
    assert "Security scan: 1 target" in result.output
    assert "[1/1] https://example.com/" in result.output


def test_scan_strict_aborts_on_the_first_invalid_target_file_line(monkeypatch, tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("example.com\nftp://unsupported.example\n")
    monkeypatch.setattr(
        "secman_web_check.cli.scan_all",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("scan ran")),
    )

    result = runner.invoke(app, ["scan", "--targets-file", str(targets_file), "--strict"])

    assert result.exit_code == 2


def test_scan_can_load_targets_from_secman(monkeypatch, tmp_path):
    loaded = []
    normalized = normalize_target("https://example.com")
    monkeypatch.setenv("SECMAN_SCANNER_ID", "42")
    monkeypatch.setattr(
        "secman_web_check.cli._targets_from_secman",
        lambda scanner_id: loaded.append(scanner_id) or (normalized,),
    )
    monkeypatch.setattr("secman_web_check.cli.scan_all", clean_run)

    result = runner.invoke(
        app,
        [
            "scan",
            "--targets-from-secman",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0, result.output
    assert loaded == [42]


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


def test_csv_scan_can_submit_results_directly_to_secman(monkeypatch, tmp_path):
    targets_csv = tmp_path / "targets.csv"
    targets_csv.write_text("awsAccountNumber,target\n111122223333,example.com\n")
    uploads = []
    monkeypatch.setattr("secman_web_check.cli.scan_all", clean_run)
    monkeypatch.setattr(
        "secman_web_check.cli._push_to_secman",
        lambda run, *, active, scanner_id, mode: uploads.append((run, active, scanner_id, mode)),
    )
    monkeypatch.setenv("SECMAN_SCANNER_ID", "42")

    result = runner.invoke(
        app,
        [
            "scan",
            "--targets-csv",
            str(targets_csv),
            "--push-to-secman",
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0, result.output
    assert uploads[0][0].targets[0].target.aws_account_number == "111122223333"
    assert uploads[0][1] is False
    assert uploads[0][2:] == (42, "security")


def test_visual_mode_is_selectable_without_running_security(monkeypatch, tmp_path):
    visual_calls = []
    monkeypatch.setattr(
        "secman_web_check.cli.scan_all",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("security ran")),
    )
    monkeypatch.setattr(
        "secman_web_check.cli.scan_visual_all",
        lambda targets, config, options, **kwargs: (
            visual_calls.append((targets, config, options)) or clean_run(targets, config, **kwargs)
        ),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--scan-mode",
            "visual",
            "--visual-no-ai",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0, result.output
    assert visual_calls[0][2].analyze is False


def test_both_mode_uploads_separate_terminal_snapshots(monkeypatch, tmp_path):
    uploads = []
    monkeypatch.setattr("secman_web_check.cli.scan_all", clean_run)
    monkeypatch.setattr(
        "secman_web_check.cli.scan_visual_all",
        lambda targets, config, _options, **kwargs: clean_run(targets, config, **kwargs),
    )
    monkeypatch.setattr(
        "secman_web_check.cli._push_to_secman",
        lambda run, *, active, scanner_id, mode: uploads.append((scanner_id, mode)),
    )
    monkeypatch.setenv("SECMAN_SECURITY_SCANNER_ID", "41")
    monkeypatch.setenv("SECMAN_VISUAL_SCANNER_ID", "42")

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--scan-mode",
            "both",
            "--visual-no-ai",
            "--push-to-secman",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0, result.output
    assert uploads == [(41, "security"), (42, "visual")]


def test_secman_loaded_target_uses_same_asset_binding_for_other_scanner(monkeypatch):
    target = replace(
        normalize_target("https://example.com"),
        secman_subject_id=4,
        secman_asset_id=9,
    )
    run = clean_run((target,), None)
    uploads = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def list_subjects(self, scanner_id):
            assert scanner_id == 42
            return [IntegrationSubject(40, 42, 9, "example.com", "https://example.com/")]

        def submit_run(self, body):
            uploads.append(body)

    monkeypatch.setattr("secman_web_check.cli._integration_client", Client)

    _push_to_secman(run, active=False, scanner_id=42, mode="visual")

    assert uploads[0]["subjectId"] == 40

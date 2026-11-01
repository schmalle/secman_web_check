import json
from hashlib import sha256

from typer.testing import CliRunner

from secman_web_check.cli import app
from secman_web_check.reports.compare import compare_reports


def report(path, findings, *, complete=True, profile="security:passive"):
    path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.3",
                "coverageManifest": {"version": 1, "rules": "fixture"},
                "profileHash": sha256(
                    json.dumps(
                        {"version": 1, "rules": "fixture"}, sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest(),
                "runId": path.stem,
                "profile": profile,
                "targets": [
                    {
                        "url": "https://example.com/",
                        "status": "SUCCESS",
                        "complete": complete,
                        "coverage": {
                            "executions": [{"check_id": "WEB-OLD", "state": "executed-negative"}]
                        },
                        "findings": [{"externalId": finding} for finding in findings],
                    }
                ],
            }
        )
    )


def test_comparison_confirms_absence_only_after_complete_matching_baseline(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    report(old, ("WEB-OLD:1",))
    report(new, ())

    assert compare_reports(old, new)["resolved"] == ["WEB-OLD:1"]
    report(new, (), complete=False)
    assert compare_reports(old, new)["unconfirmedAbsent"] == ["WEB-OLD:1"]
    report(new, (), profile="security:active")
    assert compare_reports(old, new)["unconfirmedAbsent"] == ["WEB-OLD:1"]


def test_compare_cli_emits_machine_document(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    report(old, ())
    report(new, ("WEB-NEW:2",))

    result = CliRunner().invoke(app, ["compare", str(old), str(new), "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["introduced"] == ["WEB-NEW:2"]

import csv
from datetime import UTC, datetime

from secman_web_check.models import Finding, ScanRun, Severity, TargetResult, TargetStatus
from secman_web_check.reports import write_csv
from secman_web_check.targets import normalize_target


def _finding(rule, evidence, title="Missing header"):
    return Finding(
        rule_id=rule,
        external_id=rule,
        severity=Severity.MEDIUM,
        confidence=0.9,
        title=title,
        description="multi\nline\r\ndescription",
        recommendation="Fix it",
        evidence=evidence,
        url="https://www.a.example/",
    )


def test_csv_report_writes_exactly_one_line_per_finding(tmp_path):
    now = datetime.now(UTC)
    target = normalize_target("https://www.a.example")
    run = ScanRun(
        "00000000-0000-4000-8000-000000000003",
        (
            TargetResult(
                target,
                TargetStatus.SUCCESS,
                findings=(
                    _finding("WEB-A", "line one\nline two"),
                    _finding("WEB-B", '=HYPERLINK("x")', title="@cmd"),
                ),
                started_at=now,
                completed_at=now,
            ),
            TargetResult(
                normalize_target("https://empty.example"),
                TargetStatus.SUCCESS,
                started_at=now,
                completed_at=now,
            ),
        ),
        now,
        now,
    )
    path = write_csv(run, tmp_path / "run.csv")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3  # header + one line per finding
    rows = list(csv.DictReader(lines))
    assert [row["rule_id"] for row in rows] == ["WEB-A", "WEB-B"]
    assert rows[0]["evidence"] == "line one line two"
    assert rows[0]["description"] == "multi line description"
    assert rows[1]["evidence"].startswith("'=")
    assert rows[1]["title"].startswith("'@")
    assert rows[0]["target"] == "https://www.a.example/"
    assert rows[0]["severity"] == "MEDIUM"

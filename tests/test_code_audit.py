import json

import httpx
import pytest
from typer.testing import CliRunner

from secman_web_check.cli import app
from secman_web_check.code_audit import (
    AuditError,
    GithubIssueClient,
    build_audit_run_body,
    load_audit_findings,
    publish_github_issues,
    render_issue_body,
)
from secman_web_check.models import Severity
from secman_web_check.secman import IntegrationSubject


def _confirmed(fp="sqli-1", severity="high"):
    return {
        "verdict": "confirmed",
        "fingerprint": fp,
        "title": "SQL injection @admin",
        "description": "d",
        "root_cause": "rc",
        "intended_behavior": "ib",
        "trace": [
            {"kind": "sink", "file": "src/db.py", "line": 10, "scope": "f", "description": "q"}
        ],
        "evidence": [{"file": "src/db.py", "line": 12, "description": "concat"}],
        "execution": {
            "attacker_perspective": "a",
            "payloads": ["' OR 1=1"],
            "instructions": ["send"],
            "observed_result": "dump",
        },
        "remediation": {"strategy": "parametrize"},
        "severity": {"overall_severity": severity},
        "confidence": {"score": "high"},
    }


def _write(tmp_path, records):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(records))
    return path


def test_only_confirmed_by_default_and_rejected_never(tmp_path):
    nv = {
        "verdict": "needs_validation",
        "fingerprint": "nv-1",
        "title": "t",
        "description": "d",
        "claimed_root_cause": "c",
        "trace": _confirmed()["trace"],
        "evidence": _confirmed()["evidence"],
        "blockers": ["no sandbox"],
    }
    rej = {**nv, "verdict": "rejected", "fingerprint": "rej-1", "reason": "r"}
    path = _write(tmp_path, [_confirmed(), nv, rej])
    assert [f.fingerprint for f in load_audit_findings(path)] == ["sqli-1"]
    both = load_audit_findings(path, include_needs_validation=True)
    assert {f.fingerprint for f in both} == {"sqli-1", "nv-1"}


def test_payloads_omitted_unless_opted_in_and_mentions_defused(tmp_path):
    path = _write(tmp_path, [_confirmed()])
    plain = load_audit_findings(path)[0]
    assert "OR 1=1" not in render_issue_body(plain)
    assert "@admin" not in plain.title
    detailed = load_audit_findings(path, include_exploit_detail=True)[0]
    assert "OR 1=1" in render_issue_body(detailed)
    assert plain.location == "src/db.py:10"


def test_invalid_input_fails_closed(tmp_path):
    bad = _confirmed(fp="bad fp!")
    with pytest.raises(AuditError):
        load_audit_findings(_write(tmp_path, [bad]))
    bad = _confirmed()
    bad["trace"][0]["file"] = "../etc/passwd"
    with pytest.raises(AuditError):
        load_audit_findings(_write(tmp_path, [bad]))


def test_min_severity_filter(tmp_path):
    path = _write(tmp_path, [_confirmed("a", "low"), _confirmed("b", "critical")])
    assert [f.fingerprint for f in load_audit_findings(path, min_severity=Severity.HIGH)] == ["b"]


def test_github_publish_is_idempotent_and_private_only(tmp_path, httpx_mock):
    findings = load_audit_findings(_write(tmp_path, [_confirmed("a"), _confirmed("b")]))
    httpx_mock.add_response(url="https://api.github.com/repos/o/r", json={"private": True})
    httpx_mock.add_response(
        url=httpx.URL(
            "https://api.github.com/repos/o/r/issues",
            params={"state": "all", "labels": "security-audit", "per_page": 100, "page": 1},
        ),
        json=[
            {
                "body": "<!-- secman-web-check:audit:a -->",
                "html_url": "https://github.com/o/r/issues/1",
            }
        ],
    )
    httpx_mock.add_response(
        method="POST",
        url="https://api.github.com/repos/o/r/issues",
        json={"html_url": "https://github.com/o/r/issues/2"},
    )
    with GithubIssueClient("o/r", "tok") as client:
        urls = publish_github_issues(client, findings)
    assert urls == {"a": "https://github.com/o/r/issues/1", "b": "https://github.com/o/r/issues/2"}
    assert len(httpx_mock.get_requests(method="POST")) == 1


def test_public_repo_refused(tmp_path, httpx_mock):
    findings = load_audit_findings(_write(tmp_path, [_confirmed()]))
    httpx_mock.add_response(url="https://api.github.com/repos/o/r", json={"private": False})
    with GithubIssueClient("o/r", "tok") as client, pytest.raises(AuditError):
        publish_github_issues(client, findings)


def test_secman_body_never_claims_complete_coverage(tmp_path):
    findings = load_audit_findings(_write(tmp_path, [_confirmed()]))
    subject = IntegrationSubject(1, 9, 3, "example.com", "https://example.com/")
    body = build_audit_run_body(
        9,
        subject,
        findings,
        target_url="https://example.com/",
        commit_sha="abc",
        issue_urls={"sqli-1": "https://github.com/o/r/issues/1"},
    )
    assert body["completeCoverage"] is False
    item = body["findings"][0]
    assert (item["filePath"], item["lineRange"], item["commitSha"]) == ("src/db.py", "10", "abc")
    assert item["issueUrl"].endswith("/issues/1")
    assert (
        body["runKey"]
        == build_audit_run_body(
            9,
            subject,
            findings,
            target_url="https://example.com/",
            commit_sha="abc",
            issue_urls={"sqli-1": "https://github.com/o/r/issues/1"},
        )["runKey"]
    )


def test_cli_dry_run(tmp_path):
    path = _write(tmp_path, [_confirmed()])
    out = tmp_path / "n.json"
    result = CliRunner().invoke(app, ["audit", "import", str(path), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())[0]["fingerprint"] == "sqli-1"
    missing = CliRunner().invoke(app, ["audit", "import", str(path), "--push-to-github"])
    assert missing.exit_code == 2

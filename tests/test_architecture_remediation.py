import json
from dataclasses import replace
from hashlib import sha256

import pytest
from rich.console import Console

from secman_web_check.config import ScannerConfig
from secman_web_check.coverage import manifest
from secman_web_check.models import (
    ApiOperation,
    Finding,
    JavaScriptAsset,
    ScanRun,
    Severity,
    TargetResult,
    TargetStatus,
)
from secman_web_check.reports import render_terminal, write_html, write_json, write_sarif
from secman_web_check.reports.compare import compare_reports
from secman_web_check.reports.json_report import run_document
from secman_web_check.system_review import ReviewOptions, _evidence, _parse, review_run
from secman_web_check.targets import normalize_target
from secman_web_check.visual import merge_runs


def result(url="https://example.com/?token=SYNTHETIC"):
    return TargetResult(
        normalize_target(url),
        TargetStatus.SUCCESS,
        javascript_assets=(
            JavaScriptAsset("https://cdn.example/app.js?token=SYNTHETIC", "a" * 64, 10, 200),
        ),
        api_operations=(ApiOperation("/items/{id}", "GET", "openapi", ("path:id:string",)),),
    )


def run(target=None):
    return ScanRun(
        "00000000-0000-4000-8000-000000000011",
        (target or result(),),
        manifest_json=manifest(ScannerConfig()),
    )


def test_queries_are_absent_from_every_artifact_and_provider_projection(tmp_path):
    value = run()
    evidence = json.dumps(_evidence(value.targets[0]))
    console = Console(record=True, width=160)
    render_terminal(value, console)
    artifacts = [console.export_text(), evidence]
    for writer, suffix in ((write_json, "json"), (write_html, "html"), (write_sarif, "sarif")):
        artifacts.append(writer(value, tmp_path / suffix).read_text())
    assert all("SYNTHETIC" not in item for item in artifacts)
    assert all("app.js" in item for item in artifacts)


def test_combined_merge_preserves_every_security_inventory_field():
    security = run()
    visual = replace(run(), profile="visual-capture")
    combined = merge_runs(security, visual)
    assert combined.targets[0].javascript_assets == security.targets[0].javascript_assets
    assert combined.targets[0].api_operations == security.targets[0].api_operations
    assert json.loads(combined.manifest_json)["security"]["version"] == 1


def test_later_provider_failure_preserves_finished_evidence_and_stage_attribution(
    monkeypatch, tmp_path
):
    prompt = tmp_path / "review.txt"
    prompt.write_text("Select evidence")
    original = replace(run(), targets=(result(), result("https://other.example/")))
    calls = []

    def request(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 2:
            raise ValueError("SYNTHETIC upstream secret")
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "findings": [
                                    {"category": "coverage", "evidenceIds": ["target:status"]}
                                ]
                            }
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr("secman_web_check.system_review.post_json", request)
    reviewed = review_run(original, ReviewOptions(prompt, "key", model="fixture"))
    assert len(reviewed.targets) == 2
    assert reviewed.targets[0].analysis_stages[0].state == "complete"
    assert reviewed.targets[1].analysis_stages[0].state == "failed"
    assert reviewed.targets[1].javascript_assets == original.targets[1].javascript_assets
    assert reviewed.targets[1].status == TargetStatus.PARTIAL
    assert "SYNTHETIC" not in json.dumps(run_document(reviewed))
    assert reviewed.completed_at >= original.completed_at
    finding = reviewed.targets[0].findings[0]
    assert finding.validation_status == "needs-review"
    assert finding.prompt_hash == sha256(prompt.read_bytes()).hexdigest()
    assert finding.model == "fixture"
    assert calls[0][0][2]["response_format"]["type"] == "json_schema"


def test_review_rejects_invented_evidence_and_secret_echo_and_distinguishes_references():
    target = result()
    rows = [{"category": "coverage", "evidenceIds": ["unobserved:SYNTHETIC"]}]
    payload = lambda value: {"choices": [{"message": {"content": json.dumps({"findings": value})}}]}
    with pytest.raises(ValueError, match="unobserved"):
        _parse(payload(rows), target, "fixture")
    with pytest.raises(TypeError, match="invalid evidence"):
        _parse(
            payload(
                [{"category": "coverage", "evidenceIds": ["target:status"], "title": "SYNTHETIC"}]
            ),
            target,
            "fixture",
        )
    valid = [
        {"category": "coverage", "evidenceIds": ["target:status"]},
        {"category": "coverage", "evidenceIds": ["js:" + "a" * 64]},
    ]
    findings = _parse(payload(valid), target, "fixture")
    assert len({item.external_id for item in findings}) == 2


def test_comparison_rejects_optional_analysis_absence_and_changed_limits(tmp_path):
    observation = Finding.create(
        "LLM-coverage",
        "https://example.com/",
        Severity.INFO,
        "review",
        validation_status="needs-review",
    )
    old_run = run(replace(result(), findings=(observation,)))
    old = write_json(old_run, tmp_path / "old.json")
    new = write_json(run(), tmp_path / "new.json")
    assert not compare_reports(old, new)["resolved"]
    assert compare_reports(old, new)["unconfirmedAbsent"] == [observation.external_id]
    deterministic = Finding.create("WEB-TEST", "https://example.com/", Severity.LOW, "fixture")
    write_json(run(replace(result(), findings=(deterministic,))), old)
    changed = replace(run(), manifest_json=manifest(ScannerConfig(max_body_bytes=100)))
    write_json(changed, new)
    assert not compare_reports(old, new)["comparableCoverage"]
    assert not compare_reports(old, new)["resolved"]


def test_legacy_reports_cannot_establish_resolution(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    document = run_document(run())
    document.pop("coverageManifest")
    document.pop("profileHash")
    old.write_text(json.dumps(document))
    new.write_text(json.dumps(document))
    assert compare_reports(old, new)["comparableCoverage"] is False


def test_reviewed_snapshot_has_same_advisories_and_provenance_as_local_run(monkeypatch, tmp_path):
    from secman_web_check.cli import _reviewed_snapshot

    prompt = tmp_path / "review.txt"
    prompt.write_text("Select evidence")
    monkeypatch.setattr(
        "secman_web_check.system_review.post_json",
        lambda *_args, **_kwargs: {
            "choices": [
                {
                    "message": {
                        "content": '{"findings":[{"category":"coverage","evidenceIds":["target:status"]}]}'
                    }
                }
            ]
        },
    )
    source = run()
    reviewed = review_run(source, ReviewOptions(prompt, "key"))
    snapshot = _reviewed_snapshot(source, reviewed)
    assert snapshot.targets[0].findings == reviewed.targets[0].findings
    assert snapshot.targets[0].analysis_stages == reviewed.targets[0].analysis_stages
    assert not snapshot.targets[0].complete
    assert snapshot.profile_hash == reviewed.profile_hash


def test_archive_round_trip_preserves_full_schema_and_parameterizes_sql():
    from test_storage import Connection

    from secman_web_check.storage import MariaDbStore

    source = run()
    connection = Connection()
    store = MariaDbStore(connection)
    store.save(source)
    insert = next(
        params
        for sql, params in connection.value.executions
        if sql.startswith("INSERT INTO scan_archive")
    )
    connection.value.fetchone = lambda: (insert[2],)
    assert store.export(source.run_id) == run_document(source)
    assert "javascriptAssets" in insert[2]
    assert "SYNTHETIC" not in insert[2]


def test_runtime_and_documented_migrations_are_equivalent():
    import re
    from pathlib import Path

    from secman_web_check.storage import _MIGRATIONS

    files = sorted((Path(__file__).parents[1] / "db/migrations").glob("*.sql"))
    assert len(files) == len(_MIGRATIONS)
    normalize = lambda text: re.sub(r"\s+", " ", text).strip().rstrip(";")
    for (_, runtime), path in zip(_MIGRATIONS, files, strict=True):
        assert normalize(runtime) == normalize(path.read_text())


def test_rule_execution_states_and_evidence_references_are_explicit():
    from secman_web_check.checks import CheckContext, evaluate_passive
    from secman_web_check.http import HttpRequest, HttpResponseEvidence

    response = HttpResponseEvidence(
        HttpRequest("GET", "https://example.com/"),
        200,
        (("content-type", "application/json"),),
        b"{}",
        False,
        0.0,
    )
    findings, executions = evaluate_passive(CheckContext(response))
    states = {item.check_id: item.state for item in executions}
    assert states["WEB-HEADER-CSP-MISSING"] == "unsupported"
    assert states["WEB-COOKIE-SECURE-MISSING"] == "skipped"
    assert states["WEB-CONTENT-SECRET"] == "executed-negative"
    truncated = replace(response, truncated=True)
    _, limited = evaluate_passive(CheckContext(truncated))
    assert (
        next(item for item in limited if item.check_id == "WEB-CONTENT-SECRET").state == "exhausted"
    )
    target = replace(result(), findings=findings)
    known = {item.id for item in target.evidence_records}
    assert all(
        identifier in known for finding in target.findings for identifier in finding.evidence_ids
    )


def test_archive_failure_rolls_back_summary_and_detail_rows():
    from test_storage import Connection

    from secman_web_check.storage import MariaDbStore, StorageError

    connection = Connection()
    execute = connection.value.execute

    def fail_archive(sql, params):
        if sql.startswith("INSERT INTO scan_archive"):
            raise RuntimeError("synthetic driver failure")
        execute(sql, params)

    connection.value.execute = fail_archive
    with pytest.raises(StorageError, match="persistence failed"):
        MariaDbStore(connection).save(run())
    assert connection.commits == 0 and connection.rollbacks == 1


def test_visual_batch_uses_isolated_workers_with_distinct_screenshot_indices(monkeypatch, tmp_path):
    from secman_web_check.traffic import TrafficController
    from secman_web_check.visual import VisualOptions, scan_visual_all

    calls = []
    targets = (normalize_target("https://example.com/a"), normalize_target("https://example.com/b"))

    def bounded(target, _config, **options):
        calls.append((target.url, options["_operation"], options["visual_options"].start_index))
        return TargetResult(target, TargetStatus.SUCCESS, complete=False)

    monkeypatch.setattr("secman_web_check.visual._bounded_scan_target", bounded)
    source = scan_visual_all(
        targets,
        ScannerConfig(),
        VisualOptions(tmp_path, analyze=False),
        traffic=TrafficController(ScannerConfig()),
    )
    assert [item.target for item in source.targets] == list(targets)
    assert sorted(index for _, _, index in calls) == [1, 2]
    assert all(operation == "visual" for _, operation, _ in calls)


def test_cancelled_worker_stops_without_waiting_for_target_deadline():
    from time import monotonic

    from secman_web_check.orchestrator import _bounded_scan_target
    from secman_web_check.traffic import TrafficController

    config = ScannerConfig(target_timeout_seconds=10)
    traffic = TrafficController(config)
    traffic.cancel()
    started = monotonic()
    # No manager/thread locks are sent to the worker in this early-cancel path.
    target = normalize_target("http://127.0.0.1/")
    value = _bounded_scan_target(target, config, traffic=traffic)
    assert monotonic() - started < 2
    assert not value.complete and value.errors == ("Run cancelled",)


def test_secman_resolution_requires_approved_exact_profile_and_executed_nonquery_context(
    monkeypatch,
    tmp_path,
):
    from secman_web_check.cli import _push_to_secman
    from secman_web_check.models import ExposureObservation, Reachability
    from secman_web_check.secman import IntegrationSubject

    monkeypatch.setenv("SECMAN_URL", "https://secman.example.test")
    monkeypatch.setenv("SECMAN_WEB_CHECK_OUTBOX", str(tmp_path / "queue"))
    source = run(
        replace(
            result("https://example.com/"),
            exposure=ExposureObservation(
                "https://example.com/", "https://example.com/", Reachability.REACHABLE, 200, 0
            ),
        )
    )
    uploads = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def list_subjects(self, scanner_id):
            return [IntegrationSubject(1, scanner_id, 2, "example.com", "https://example.com/")]

        def submit_run(self, body):
            uploads.append(body)
            return {"id": 1, "scannerId": body["scannerId"], "subjectId": body["subjectId"]}

    monkeypatch.setattr("secman_web_check.cli._integration_client", Client)
    monkeypatch.delenv("SECMAN_BASELINE_PROFILE_SHA256", raising=False)
    _push_to_secman(source, active=False, scanner_id=1, mode="security")
    assert uploads[-1]["completeCoverage"] is False
    monkeypatch.setenv("SECMAN_BASELINE_PROFILE_SHA256", source.profile_hash)
    _push_to_secman(source, active=False, scanner_id=1, mode="security")
    assert uploads[-1]["completeCoverage"] is True
    changed = replace(source, manifest_json=manifest(ScannerConfig(max_body_bytes=100)))
    _push_to_secman(changed, active=False, scanner_id=1, mode="security")
    assert uploads[-1]["completeCoverage"] is False
    query_context = replace(
        source,
        targets=(
            replace(
                source.targets[0], coverage=replace(source.targets[0].coverage, query_input=True)
            ),
        ),
    )
    _push_to_secman(query_context, active=False, scanner_id=1, mode="security")
    assert uploads[-1]["completeCoverage"] is False


def test_review_cancellation_retains_earlier_observations_and_stops_later_calls(
    monkeypatch, tmp_path
):
    from secman_web_check.traffic import TrafficController

    prompt = tmp_path / "review.txt"
    prompt.write_text("Select known evidence")
    source = replace(
        run(),
        targets=(result(), result("https://second.example/"), result("https://third.example/")),
    )
    calls = []

    def request(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return {
            "choices": [
                {
                    "message": {
                        "content": '{"findings":[{"category":"coverage","evidenceIds":["target:status"]}]}'
                    }
                }
            ]
        }

    monkeypatch.setattr("secman_web_check.system_review.post_json", request)
    traffic = TrafficController(ScannerConfig())
    reviewed = review_run(source, ReviewOptions(prompt, "key"), traffic=traffic)
    assert len(calls) == 2 and traffic.cancelled
    assert reviewed.targets[0].findings
    assert reviewed.targets[0].analysis_stages[0].state == "complete"
    assert all(target.analysis_stages[0].state == "cancelled" for target in reviewed.targets[1:])
    assert all(target.javascript_assets for target in reviewed.targets)


@pytest.mark.parametrize("engine", ["security", "visual"])
def test_batch_cancellation_keeps_finished_results_and_terminates_pending_work(
    monkeypatch, tmp_path, engine
):
    import time

    from secman_web_check import orchestrator, visual
    from secman_web_check.traffic import TrafficController

    config = ScannerConfig(concurrency=2)
    traffic = TrafficController(config)
    targets = (
        normalize_target("https://finished.example/"),
        normalize_target("https://pending.example/"),
    )

    def worker(target, _config, **_options):
        if target.host == "pending.example":
            while not traffic.cancelled:
                time.sleep(0.005)
            return TargetResult(
                target, TargetStatus.FAILED, errors=("Run cancelled",), complete=False
            )
        return TargetResult(target, TargetStatus.SUCCESS)

    def interrupted(futures):
        yield next(iter(futures))
        raise KeyboardInterrupt

    module = orchestrator if engine == "security" else visual
    monkeypatch.setattr(module, "_bounded_scan_target", worker)
    monkeypatch.setattr(module, "as_completed", interrupted)
    if engine == "security":
        scanned = orchestrator.scan_all(targets, config, traffic=traffic)
    else:
        scanned = visual.scan_visual_all(
            targets, config, visual.VisualOptions(tmp_path, analyze=False), traffic=traffic
        )
    assert traffic.cancelled
    assert scanned.targets[0].status == TargetStatus.SUCCESS
    assert scanned.targets[1].status == TargetStatus.FAILED
    assert scanned.targets[1].errors == ("Run cancelled",)


def test_comparison_never_resolves_a_rule_evaluated_on_a_different_effective_page(tmp_path):
    from secman_web_check.models import CheckExecution, CoverageSummary

    old_finding = Finding.create(
        "WEB-HEADER-CSP-MISSING", "https://example.com/old", Severity.MEDIUM, "CSP"
    )
    previous = run(replace(result("https://example.com/"), findings=(old_finding,)))
    current = run(
        replace(
            result("https://example.com/"),
            coverage=CoverageSummary(
                executions=(
                    CheckExecution(
                        "WEB-HEADER-CSP-MISSING", "https://example.com/new", "executed-negative"
                    ),
                )
            ),
        )
    )
    old = write_json(previous, tmp_path / "old.json")
    new = write_json(current, tmp_path / "new.json")
    compared = compare_reports(old, new)
    assert not compared["resolved"]
    assert compared["unconfirmedAbsent"] == [old_finding.external_id]

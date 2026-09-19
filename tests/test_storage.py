from datetime import UTC, datetime

from secman_web_check.models import (
    ComponentCategory,
    DetectedComponent,
    ExposureObservation,
    Finding,
    Reachability,
    ScanRun,
    Severity,
    TargetResult,
    TargetStatus,
)
from secman_web_check.storage import MariaDbStore
from secman_web_check.targets import normalize_target


class Cursor:
    def __init__(self):
        self.executions = []
        self.lastrowid = 7

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def close(self):
        pass


class Connection:
    def __init__(self):
        self.value = Cursor()
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self.value

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_store_parameterizes_target_controlled_values():
    target = normalize_target("https://example.com/path?input=attack")
    finding = Finding.create("WEB-TEST", target.url, Severity.LOW, "test")
    component = DetectedComponent.create(
        ComponentCategory.WEB_SERVER,
        "nginx",
        version="1.25.4",
        confidence=0.9,
        evidence_type="HTTP_HEADER",
        evidence="Server header matched nginx",
    )
    now = datetime.now(UTC)
    run = ScanRun(
        "00000000-0000-4000-8000-000000000003",
        (
            TargetResult(
                target,
                TargetStatus.SUCCESS,
                (finding,),
                components=(component,),
                exposure=ExposureObservation(
                    "https://example.com/path",
                    "https://example.com/path",
                    Reachability.REACHABLE,
                    200,
                    0,
                    body_length=512,
                ),
                inventory_complete=True,
                started_at=now,
                completed_at=now,
            ),
        ),
        now,
        now,
    )
    connection = Connection()
    MariaDbStore(connection).save(run)
    assert connection.commits == 1
    assert any(
        "https://example.com/path" in params
        for _sql, params in connection.value.executions
        if params
    )
    target_inserts = [
        params
        for sql, params in connection.value.executions
        if sql.startswith("INSERT INTO scan_target")
    ]
    assert all(target.url not in params for params in target_inserts)
    assert all(target.url not in sql for sql, _params in connection.value.executions)
    assert any(512 in params for params in target_inserts)
    assert any(
        component.component_key in params for _sql, params in connection.value.executions if params
    )

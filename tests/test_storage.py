from datetime import UTC, datetime

from secman_web_check.models import Finding, ScanRun, Severity, TargetResult, TargetStatus
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
    now = datetime.now(UTC)
    run = ScanRun(
        "00000000-0000-4000-8000-000000000003",
        (
            TargetResult(
                target,
                TargetStatus.SUCCESS,
                (finding,),
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
    assert any(target.url in params for _sql, params in connection.value.executions if params)
    assert all(target.url not in sql for sql, _params in connection.value.executions)

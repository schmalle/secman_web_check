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


def test_database_uses_verified_tls_with_system_trust(monkeypatch):
    import ssl

    import pymysql

    from secman_web_check.storage import DatabaseSettings, connect_database

    captured = {}
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: captured.update(kwargs))
    connect_database(DatabaseSettings("db.example.com", "scanner", "secret"))
    context = captured["ssl"]
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.get_ca_certs()


def test_database_without_ssl_support_fails_before_authentication():
    import ssl

    import pytest
    from pymysql.connections import Connection as DriverConnection
    from pymysql.err import OperationalError

    connection = DriverConnection(
        host="db.example.com",
        user="scanner",
        password="secret",
        ssl=ssl.create_default_context(),
        defer_connect=True,
    )
    connection.server_version = "8.0.0"
    connection.server_capabilities = 0
    packets = []
    connection.write_packet = packets.append
    with pytest.raises(OperationalError, match="SSL is required"):
        connection._request_authentication()
    assert packets == []


def test_database_custom_ca_and_ca_errors_are_sanitized(monkeypatch):
    import ssl

    import pymysql
    import pytest

    from secman_web_check.storage import DatabaseSettings, StorageError, connect_database

    original = ssl.create_default_context
    seen = []

    def context(*, cafile):
        seen.append(cafile)
        return original()

    monkeypatch.setattr(ssl, "create_default_context", context)
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: kwargs["ssl"])
    verified = connect_database(
        DatabaseSettings("db.example.com", "scanner", "secret", ssl_ca="private-ca.pem")
    )
    assert seen == ["private-ca.pem"]
    assert verified.check_hostname and verified.verify_mode == ssl.CERT_REQUIRED
    monkeypatch.setattr(
        ssl,
        "create_default_context",
        lambda **kwargs: (_ for _ in ()).throw(OSError("private-ca.pem sensitive")),
    )
    with pytest.raises(StorageError, match="^MariaDB connection failed$"):
        connect_database(DatabaseSettings("db.example.com", "scanner", "secret"))

"""Optional MariaDB scan history with parameterized writes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .components import sanitize_inventory_url
from .models import ScanRun


class StorageError(RuntimeError):
    """Raised for sanitized storage failures."""


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    host: str
    user: str
    password: str = field(repr=False)
    database: str = "secman_web_check"
    port: int = 3306
    ssl_ca: str | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> DatabaseSettings:
        try:
            return cls(
                host=environ["SECMAN_WEB_CHECK_DB_HOST"],
                user=environ["SECMAN_WEB_CHECK_DB_USER"],
                password=environ["SECMAN_WEB_CHECK_DB_PASSWORD"],
                database=environ.get("SECMAN_WEB_CHECK_DB_NAME", "secman_web_check"),
                port=int(environ.get("SECMAN_WEB_CHECK_DB_PORT", "3306")),
                ssl_ca=environ.get("SECMAN_WEB_CHECK_DB_SSL_CA"),
            )
        except (KeyError, ValueError) as error:
            raise StorageError(
                "MariaDB environment configuration is incomplete or invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class SchemaStatus:
    installed: bool
    version: int | None


@dataclass(frozen=True, slots=True)
class StoredRunSummary:
    run_id: str
    started_at: datetime
    completed_at: datetime
    target_count: int
    finding_count: int
    component_count: int


_MIGRATION_V1 = """
CREATE TABLE IF NOT EXISTS schema_version (
  version INT PRIMARY KEY,
  checksum CHAR(64) NOT NULL,
  installed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS scan_run (
  run_id CHAR(36) PRIMARY KEY,
  started_at DATETIME(6) NOT NULL,
  completed_at DATETIME(6) NOT NULL,
  target_count INT NOT NULL,
  finding_count INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS scan_target (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  run_id CHAR(36) NOT NULL,
  url VARCHAR(2048) NOT NULL,
  status VARCHAR(16) NOT NULL,
  complete_coverage BOOLEAN NOT NULL,
  errors_json TEXT NOT NULL,
  started_at DATETIME(6) NOT NULL,
  completed_at DATETIME(6) NOT NULL,
  UNIQUE KEY uq_scan_target_run_url (run_id, url(512)),
  KEY ix_scan_target_status (status),
  CONSTRAINT fk_scan_target_run FOREIGN KEY (run_id) REFERENCES scan_run(run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS scan_finding (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  scan_target_id BIGINT UNSIGNED NOT NULL,
  external_id VARCHAR(128) NOT NULL,
  rule_id VARCHAR(128) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  confidence DOUBLE NOT NULL,
  title VARCHAR(512) NOT NULL,
  description TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  evidence VARCHAR(512) NOT NULL,
  url VARCHAR(2048) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  UNIQUE KEY uq_scan_finding_target_external (scan_target_id, external_id),
  KEY ix_scan_finding_severity (severity),
  KEY ix_scan_finding_external (external_id),
  CONSTRAINT fk_scan_finding_target FOREIGN KEY (scan_target_id) REFERENCES scan_target(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
""".strip()

_MIGRATION_V2 = """
ALTER TABLE scan_run
  ADD COLUMN IF NOT EXISTS component_count INT NOT NULL DEFAULT 0;
ALTER TABLE scan_target
  ADD COLUMN IF NOT EXISTS effective_url VARCHAR(2048) NULL,
  ADD COLUMN IF NOT EXISTS reachability VARCHAR(16) NULL,
  ADD COLUMN IF NOT EXISTS http_status SMALLINT UNSIGNED NULL,
  ADD COLUMN IF NOT EXISTS redirect_count INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS vantage_point VARCHAR(100) NULL,
  ADD COLUMN IF NOT EXISTS inventory_complete BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS scan_component (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  scan_target_id BIGINT UNSIGNED NOT NULL,
  component_key VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
  category VARCHAR(32) NOT NULL,
  name VARCHAR(255) NOT NULL,
  version VARCHAR(100) NULL,
  confidence DOUBLE NOT NULL,
  evidence_type VARCHAR(32) NOT NULL,
  evidence VARCHAR(512) NOT NULL,
  source_url VARCHAR(2048) NULL,
  UNIQUE KEY uq_scan_component_target_key (scan_target_id, component_key),
  KEY ix_scan_component_category_name (category, name),
  CONSTRAINT fk_scan_component_target FOREIGN KEY (scan_target_id) REFERENCES scan_target(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
""".strip()

_MIGRATION_V3 = """
ALTER TABLE scan_target
  ADD COLUMN IF NOT EXISTS body_length INT UNSIGNED NULL
""".strip()

_MIGRATIONS = ((1, _MIGRATION_V1), (2, _MIGRATION_V2), (3, _MIGRATION_V3))


def connect_database(settings: DatabaseSettings) -> Any:
    try:
        import pymysql  # type: ignore[import-untyped]

        ssl = {"ca": settings.ssl_ca} if settings.ssl_ca else None
        return pymysql.connect(
            host=settings.host,
            port=settings.port,
            user=settings.user,
            password=settings.password,
            database=settings.database,
            charset="utf8mb4",
            autocommit=False,
            ssl=ssl,
        )
    except Exception as error:
        raise StorageError("MariaDB connection failed") from error


class MariaDbStore:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def install(self) -> None:
        cursor = self.connection.cursor()
        try:
            schema_statement = _MIGRATION_V1.split(";", 1)[0].strip()
            cursor.execute(schema_statement)
            for version, migration in _MIGRATIONS:
                checksum = hashlib.sha256(migration.encode()).hexdigest()
                cursor.execute("SELECT checksum FROM schema_version WHERE version = %s", (version,))
                row = cursor.fetchone()
                if row is not None:
                    existing = row[0] if not isinstance(row, dict) else row["checksum"]
                    if existing != checksum:
                        raise StorageError("MariaDB migration checksum mismatch")
                    continue
                statements = tuple(
                    statement.strip() for statement in migration.split(";") if statement.strip()
                )
                for statement in statements[1:] if version == 1 else statements:
                    cursor.execute(statement)
                cursor.execute(
                    "INSERT INTO schema_version (version, checksum) VALUES (%s, %s)",
                    (version, checksum),
                )
            self.connection.commit()
        except StorageError:
            self.connection.rollback()
            raise
        except Exception as error:
            self.connection.rollback()
            raise StorageError("MariaDB schema installation failed") from error
        finally:
            cursor.close()

    def status(self) -> SchemaStatus:
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT MAX(version) FROM schema_version")
            row = cursor.fetchone()
            version = (
                None
                if not row
                else (row[0] if not isinstance(row, dict) else next(iter(row.values())))
            )
            return SchemaStatus(version is not None, None if version is None else int(version))
        except Exception:  # noqa: BLE001 - missing schema and driver errors mean not installed
            return SchemaStatus(False, None)
        finally:
            cursor.close()

    def save(self, run: ScanRun) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO scan_run (run_id, started_at, completed_at, target_count, finding_count, component_count) VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    run.run_id,
                    run.started_at,
                    run.completed_at,
                    len(run.targets),
                    sum(len(target.findings) for target in run.targets),
                    sum(len(target.components) for target in run.targets),
                ),
            )
            for target in run.targets:
                exposure = target.exposure
                cursor.execute(
                    "INSERT INTO scan_target (run_id, url, effective_url, reachability, http_status, redirect_count, body_length, vantage_point, inventory_complete, status, complete_coverage, errors_json, started_at, completed_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        run.run_id,
                        exposure.configured_url
                        if exposure is not None
                        else (sanitize_inventory_url(target.target.url) or target.target.url),
                        exposure.effective_url if exposure is not None else None,
                        exposure.reachability.value if exposure is not None else None,
                        exposure.http_status if exposure is not None else None,
                        exposure.redirect_count if exposure is not None else 0,
                        exposure.body_length if exposure is not None else None,
                        exposure.vantage_point if exposure is not None else None,
                        target.inventory_complete,
                        target.status.value,
                        target.complete,
                        json.dumps(target.errors),
                        target.started_at,
                        target.completed_at,
                    ),
                )
                target_id = cursor.lastrowid
                for finding in target.findings:
                    cursor.execute(
                        "INSERT INTO scan_finding (scan_target_id, external_id, rule_id, severity, confidence, title, description, recommendation, evidence, url, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            target_id,
                            finding.external_id,
                            finding.rule_id,
                            finding.severity.value,
                            finding.confidence,
                            finding.title,
                            finding.description,
                            finding.recommendation,
                            finding.evidence,
                            finding.url,
                            finding.created_at,
                        ),
                    )
                for component in target.components:
                    cursor.execute(
                        "INSERT INTO scan_component (scan_target_id, component_key, category, name, version, confidence, evidence_type, evidence, source_url) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            target_id,
                            component.component_key,
                            component.category.value,
                            component.name,
                            component.version,
                            component.confidence,
                            component.evidence_type,
                            component.evidence,
                            component.source_url,
                        ),
                    )
            self.connection.commit()
        except Exception as error:
            self.connection.rollback()
            raise StorageError("MariaDB scan persistence failed") from error
        finally:
            cursor.close()

    def list_runs(self, limit: int = 50) -> tuple[StoredRunSummary, ...]:
        if limit < 1 or limit > 500:
            raise ValueError("history limit must be between 1 and 500")
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT run_id, started_at, completed_at, target_count, finding_count, component_count FROM scan_run ORDER BY started_at DESC LIMIT %s",
                (limit,),
            )
            return tuple(StoredRunSummary(*row) for row in cursor.fetchall())
        except Exception as error:
            raise StorageError("MariaDB history query failed") from error
        finally:
            cursor.close()


__all__ = [
    "DatabaseSettings",
    "MariaDbStore",
    "SchemaStatus",
    "StorageError",
    "StoredRunSummary",
    "connect_database",
]

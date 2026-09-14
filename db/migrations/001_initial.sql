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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

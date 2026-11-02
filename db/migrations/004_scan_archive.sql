CREATE TABLE IF NOT EXISTS scan_archive (
  run_id CHAR(36) PRIMARY KEY,
  schema_version VARCHAR(16) NOT NULL,
  report_json LONGTEXT NOT NULL,
  CONSTRAINT fk_scan_archive_run FOREIGN KEY (run_id) REFERENCES scan_run(run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4

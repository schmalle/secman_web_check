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
  CONSTRAINT fk_scan_component_target FOREIGN KEY (scan_target_id)
    REFERENCES scan_target(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

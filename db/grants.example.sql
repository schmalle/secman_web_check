CREATE DATABASE IF NOT EXISTS secman_web_check CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS 'scanner_user'@'scanner_host' IDENTIFIED BY 'replace-this-secret';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX
  ON secman_web_check.* TO 'scanner_user'@'scanner_host';

# MariaDB history

Persistence is disabled unless the operator invokes a database/history command or uses
`--store-db`. MariaDB is the only supported database backend.

1. Review [the example grants](../db/grants.example.sql) and replace every placeholder.
2. Create the database/user with an administrative account outside this tool.
3. Export the scanner's least-privilege connection variables described in
   [CONFIGURATION.md](CONFIGURATION.md).
4. Run `./scripts/install-db.sh`, then `secman-web-check db status`.
5. Add `--store-db` only to scans whose history should be retained.

The schema stores version/checksum metadata, scan runs, explicit targets, normalized
findings, completeness, and sanitized errors. All target-controlled values use DB-API
parameters. A run write is transactional; a failure rolls it back and returns exit code
2 without removing reports already generated on disk.

Use a trusted CA with `SECMAN_WEB_CHECK_DB_SSL_CA` when the database requires TLS. The
scanner never prints or persists the database password.

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
findings, exposure observations, normalized components, completeness, and sanitized
errors. Component inventory is stored per run and is not treated as a vulnerability.
All target-controlled values use DB-API parameters. A run write is transactional; a
failure rolls it back and returns exit code 2 without removing reports already generated
on disk.

All database connections require TLS with certificate and hostname verification. System trust
roots are used by default; set `SECMAN_WEB_CHECK_DB_SSL_CA` for a private CA. Servers without
TLS support and untrusted certificates fail before authentication; plaintext fallback is disabled. The
scanner never prints or persists the database password.


## Schema 4: full JSON archives

Migration `004_scan_archive.sql` adds `scan_archive`, linked to `scan_run` with cascading
deletion. A save inserts normalized summaries and a full schema 1.3 JSON document in one
transaction. Archive failure rolls back all rows. Run `db install` before saving with
this implementation. Existing migration checksums are unchanged.

`history export RUN_ID --output report.json` exports the full archived record, including
coverage, API/script inventory, evidence IDs and model/prompt/policy attribution. Older
runs without archives fail explicitly as summary-only; missing fields are never invented.
Archives are capped at 20 MB. Runtime and SQL migration definitions have a parity test.

Retention remains operator-controlled. Removing a run through an approved database
retention procedure also removes its archive; screenshots are separate local artifacts
and need independent retention. Neither archive nor summary tables store raw page bodies.

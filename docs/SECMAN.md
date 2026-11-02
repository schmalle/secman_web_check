# SecMan REST integration

SecMan upload is disabled unless `--push-to-secman` is supplied. This is the direct
result-import path; no separate export/import step is required.

1. Register a `WEB_SECURITY` scanner for baseline security results, a second
   `WEB_SECURITY` scanner for extended checks, and a `VISUAL` scanner for visual results
   when those modes are needed.
2. Assign their service users and bind only authorized asset subjects.
3. Set `SECMAN_URL` to the HTTPS origin plus `SECMAN_SECURITY_SCANNER_ID`,
   `SECMAN_EXTENDED_SCANNER_ID`, and/or `SECMAN_VISUAL_SCANNER_ID` for selected modes.
4. Set `SECMAN_TOKEN`, or set `SECMAN_USERNAME` and `SECMAN_PASSWORD`.
5. Run a local JSON report first, then repeat with `--push-to-secman`.

The client discovers subjects through
`GET /api/integrations/v1/scanners/{id}/subjects` and submits atomic target snapshots to
`POST /api/integrations/v1/runs`. Matching prefers the normalized URI and falls back to
the canonical hostname. For `--targets-csv`, the AWS account number first
narrows the authorized subject list by `cloudAccountId`, preventing a same-hostname
asset in another account from being selected. Missing or ambiguous matches fail safely.
No inventory is created and no legacy endpoint is attempted.

Use `--targets-from-secman` to scan the URI-bearing subjects returned by that discovery
call. The scanner retains the exact subject/asset binding through the run; subjects
without a URI are skipped rather than guessed, and no asset is created or auto-bound.

`WEB_SECURITY` snapshots include an additive inventory block containing the current
exposure observation and detected JavaScript libraries, CSS libraries, and web servers.
The local report retains received body length and the legacy `AUTHENTICATED` label
for the AWS API Gateway `Missing Authentication Token` response. REST v1 sends
`REACHABLE` with an authentication-required metadata flag; it does not assert
authenticated access.
Inventory coverage is independent of finding coverage. A successful complete inventory
snapshot may resolve an absent component; partial, failed, or truncated collection never
does. Visual snapshots do not submit component inventory.
Visual uploads always set finding `completeCoverage=false`: model observations and
screenshot-only runs cannot prove that an older visual finding is absent.

Baseline resolution requires a complete successful passive target, an eligible non-query
HTTP-200 context without redirects, plus an exact operator-approved `SECMAN_BASELINE_PROFILE_SHA256` matching the
report's canonical profile hash. Without that approval, finding and inventory snapshots
are non-terminal. This protects lifecycle boundaries when remote REST v1 does not enforce
manifest equivalence. Review catalogue, scope and limits before approving a changed hash.
Partial and failed results set `completeCoverage=false`, so they never resolve older
findings. Stable external IDs and deterministic run keys make a retry idempotent.

Active probes, TLS vulnerability probes, crawling, browser discovery, JavaScript inventory,
system review, directory discovery, external scanners, and AI agent runs use
`SECMAN_EXTENDED_SCANNER_ID` with a separate `WEB_SECURITY` registration. Their upload
sets finding and inventory `completeCoverage=false` until SecMan has a profile-aware
coverage contract. This prevents selective checks from resolving older findings. Bind
the same authorized assets to the extended registration before using
`--targets-from-secman` for an extended run. Local reports retain actual scan status.

TLS verification is mandatory. Authentication failures and response errors are
sanitized; tokens, passwords, cookies, and raw web response bodies are not uploaded.
Inventory source URLs have no query or fragment, and fixed signature evidence replaces
raw header values. SecMan exposes inventory over its REST v1 and MCP read APIs; there is
no SOAP adapter.

Security and visual results intentionally use separate scanner registrations. A
combined run submits two atomic snapshots; the merged local report is not uploaded as
a third snapshot. This prevents a security-only run from resolving visual findings, or
the reverse. `SECMAN_SCANNER_ID` remains a compatibility fallback only for a
single-mode baseline or visual run.

## Proton Pass credentials

The wrapper follows SecMan's `scripts/import.sh` pattern: `pass-cli` resolves references
into a child process environment, then the scanner runs with `--push-to-secman`.

```bash
cp examples/secman-proton-pass.env .env
${EDITOR:-vi} .env
pass-cli login
./scripts/scan-with-proton-pass.sh \
  --targets-csv testdata/targets-aws.csv \
  --format json \
  --output-dir scan-output \
  --fail-on none
```

The reference file must resolve `SECMAN_URL`, the scanner ID(s) required by the chosen
mode, and either
`SECMAN_TOKEN` or the pair `SECMAN_USERNAME` and `SECMAN_PASSWORD`. Do not put resolved
passwords or tokens in the file. Select another file with `--env-file FILE` or
`SECMAN_WEB_CHECK_PASS_ENV_FILE`; select another executable with `SECMAN_PASS_CLI`.

## AWS Secrets Manager credentials

For production, store the required variables in one JSON `SecretString`. Supported
keys are the SecMan URL, scanner IDs, token or username/password, and optional vision
provider settings. Then run:

```bash
./scripts/scan-with-aws-secrets.py --secret-id prod/secman/web-check -- \
  https://example.com --scan-mode both --format json --fail-on none
```

The script relies on the standard AWS CLI credential chain, rejects unknown JSON keys,
does not echo the secret response, and passes resolved values only in the child process
environment.

## AWS target CSV

`--targets-csv` accepts UTF-8 CSV with this exact header:

```csv
awsAccountNumber,target
111122223333,https://example.com/
444455556666,service.example.org
```

Each account number must contain 9 to 12 digits and each target must pass the normal URL
and network-policy validation. A target cell may list several whitespace-separated
targets; each is handled as its own row under the same account number. Blank targets,
unexpected columns, malformed rows, and the same normalized target assigned to
different accounts are rejected before scanning.
The account is included in the JSON report and in the SecMan subject-selection step.
A ready-to-edit example is available at `testdata/targets-aws.csv`.


Schema 1.3 evidence/coverage, scripts, API inventory and analysis provenance are carried
in snapshot metadata without changing REST v1 top-level fields. Review additions reach
the primary security snapshot (or visual snapshot in visual-only mode), preserving
separate mode lifecycles. They remain non-terminal and require human review. All baseline
profiles are non-terminal unless the exact hash is approved through the environment.

## Durable delivery and standalone report upload

`--push-to-secman` now retains JSON plus a private SQLite delivery queue before upload.
`--defer-secman` (with `--push-to-secman`) queues without contacting SecMan; an explicitly
configured `SECMAN_URL` identifies the destination, but credentials are not needed until
retry. Standalone scans still make no SecMan calls. Subject discovery remains a separate
explicit network operation and fails closed when unavailable.

```sh
secman-web-check scan https://example.com --push-to-secman --defer-secman --format json
secman-web-check delivery status
secman-web-check delivery retry
secman-web-check delivery retry --resume-blocked
secman-web-check delivery upload --report scan.json --scanner-id 41 --mode security
secman-web-check delivery upload --report scan.json --scanner-id 41 --mode security --defer
```

Mode is `security`, `security-extended`, or `visual`. Combined reports are for local
review: upload the separate `*-security.json` and `*-visual.json` mode reports instead.
The JSON export preserves exact subject/asset IDs discovered from SecMan. The existing
account-first URI/hostname matching remains available for direct targets without IDs.
An already prepared delivery is never remapped on retry.

`SECMAN_WEB_CHECK_OUTBOX` selects the private queue directory, defaulting to
`~/.local/state/secman-web-check/delivery`. The POSIX queue uses stdlib SQLite, contains
no credentials, and serializes senders with a file lock. Bounds: 1,000 records, 256 MiB
of templates, 8 MiB per template. There is no automatic purge. Archive acknowledged
queues deliberately; never discard pending records to make room.

Timeouts, HTTP 429 and transient failures are retried with backoff; permanent errors
remain blocked. Correct the problem before `--resume-blocked`. v1 rejects a delayed
snapshot older than its latest accepted run; the queue retains that rejection without
changing timestamps. Late history-only ingestion is a future v2 capability.

Local DB persistence and each mode's upload are attempted independently. A synchronous
failure exits 2; deferred delivery leaves the scan outcome in control of the exit code.
Status output distinguishes pending, blocked and delivered records without printing
payloads or credentials.

REST v1 exposure sends only supported fields: body length stays in the local report.
The legacy local `AUTHENTICATED` observation maps to central `REACHABLE` with
`authenticationRequired` in run metadata; it never means a successful authenticated
session or grants complete coverage. Metadata uses bounded counts/profile attribution;
full discovery evidence stays in the local JSON archive. Baseline resolution still
requires the exact approved profile, a successful complete HTTP-200 observation,
no redirects and no query context. Extended and visual results never resolve by absence.

Saved-report uploads are always non-resolving: report fields are assertions, not
proof that an approved baseline ran. Live passive uploads require a nonempty
approved profile hash matching the recomputed manifest. Imported asset IDs must
also match the target URL/hostname and supplied account.

For an irrecoverable blocked request (for example a late snapshot rejected with
409), inspect `delivery status`, then run
`secman-web-check delivery quarantine --delivery-id ID`. This retains the
request and error locally but allows later deliveries to proceed. Quarantine
only after deciding that this request should never be retried; it is not an
acknowledgement that SecMan accepted it.

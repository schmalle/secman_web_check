# SecMan REST integration

SecMan upload is disabled unless `--push-to-secman` is supplied. This is the direct
result-import path; no separate export/import step is required.

1. Register a `WEB_SECURITY` scanner for security results and a `VISUAL` scanner for
   visual results.
2. Assign their service users and bind only authorized asset subjects.
3. Set `SECMAN_URL` to the HTTPS origin plus `SECMAN_SECURITY_SCANNER_ID` and/or
   `SECMAN_VISUAL_SCANNER_ID` for the selected modes.
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
The exposure observation carries the received body length and marks a URL as
`AUTHENTICATED` when the body is exactly the AWS API Gateway
`Missing Authentication Token` response.
Inventory coverage is independent of finding coverage. A successful complete inventory
snapshot may resolve an absent component; partial, failed, or truncated collection never
does. Visual snapshots do not submit component inventory.

A complete successful target may resolve older absent findings for that scanner/subject.
Partial and failed results set `completeCoverage=false`, so they never resolve older
findings. Stable external IDs and deterministic run keys make a retry idempotent.

TLS verification is mandatory. Authentication failures and response errors are
sanitized; tokens, passwords, cookies, and raw web response bodies are not uploaded.
Inventory source URLs have no query or fragment, and fixed signature evidence replaces
raw header values. SecMan exposes inventory over its REST v1 and MCP read APIs; there is
no SOAP adapter.

Security and visual results intentionally use separate scanner registrations. A
combined run submits two atomic snapshots; the merged local report is not uploaded as
a third snapshot. This prevents a security-only run from resolving visual findings, or
the reverse. `SECMAN_SCANNER_ID` remains a compatibility fallback only for a
single-mode run.

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

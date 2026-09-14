# SecMan REST integration

SecMan upload is disabled unless `--push-to-secman` is supplied. This is the direct
result-import path; no separate export/import step is required.

1. Register an integration scanner whose source is `WEB_SECURITY`.
2. Assign its service user and bind only authorized asset subjects.
3. Set `SECMAN_URL` to the HTTPS origin and `SECMAN_SCANNER_ID` to the registration ID.
4. Set `SECMAN_TOKEN`, or set `SECMAN_USERNAME` and `SECMAN_PASSWORD`.
5. Run a local JSON report first, then repeat with `--push-to-secman`.

The client discovers subjects through
`GET /api/integrations/v1/scanners/{id}/subjects` and submits atomic target snapshots to
`POST /api/integrations/v1/runs`. Matching prefers the normalized URI and falls back to
the canonical hostname. For `--targets-csv`, the 12-digit AWS account number first
narrows the authorized subject list by `cloudAccountId`, preventing a same-hostname
asset in another account from being selected. Missing or ambiguous matches fail safely.
No inventory is created and no legacy endpoint is attempted.

A complete successful target may resolve older absent findings for that scanner/subject.
Partial and failed results set `completeCoverage=false`, so they never resolve older
findings. Stable external IDs and deterministic run keys make a retry idempotent.

TLS verification is mandatory. Authentication failures and response errors are
sanitized; tokens, passwords, cookies, and raw web response bodies are not uploaded.

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

The reference file must resolve `SECMAN_URL`, `SECMAN_SCANNER_ID`, and either
`SECMAN_TOKEN` or the pair `SECMAN_USERNAME` and `SECMAN_PASSWORD`. Do not put resolved
passwords or tokens in the file. Select another file with `--env-file FILE` or
`SECMAN_WEB_CHECK_PASS_ENV_FILE`; select another executable with `SECMAN_PASS_CLI`.

## AWS target CSV

`--targets-csv` accepts UTF-8 CSV with this exact header:

```csv
awsAccountNumber,target
111122223333,https://example.com/
444455556666,service.example.org
```

Each account number must be exactly 12 digits and each target must pass the normal URL
and network-policy validation. Blank targets, unexpected columns, malformed rows, and
the same normalized target assigned to different accounts are rejected before scanning.
The account is included in the JSON report and in the SecMan subject-selection step.
A ready-to-edit example is available at `testdata/targets-aws.csv`.

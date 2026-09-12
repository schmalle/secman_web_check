# SecMan REST integration

SecMan upload is disabled unless `--push-to-secman` is supplied.

1. Register an integration scanner whose source is `WEB_SECURITY`.
2. Assign its service user and bind only authorized asset subjects.
3. Set `SECMAN_URL` to the HTTPS origin and `SECMAN_SCANNER_ID` to the registration ID.
4. Set `SECMAN_TOKEN`, or set `SECMAN_USERNAME` and `SECMAN_PASSWORD`.
5. Run a local JSON report first, then repeat with `--push-to-secman`.

The client discovers subjects through
`GET /api/integrations/v1/scanners/{id}/subjects` and submits atomic target snapshots to
`POST /api/integrations/v1/runs`. Matching prefers the normalized URI and falls back to
the canonical hostname. Missing or ambiguous matches fail safely. No inventory is
created and no legacy endpoint is attempted.

A complete successful target may resolve older absent findings for that scanner/subject.
Partial and failed results set `completeCoverage=false`, so they never resolve older
findings. Stable external IDs and deterministic run keys make a retry idempotent.

TLS verification is mandatory. Authentication failures and response errors are
sanitized; tokens, passwords, cookies, and raw web response bodies are not uploaded.

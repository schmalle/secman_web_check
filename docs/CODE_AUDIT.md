# Cloudflare security-audit-skill import

[`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill)
audits *source code* and writes a schema-validated `findings.json`. This scanner does not
run it. `secman-web-check audit import` reads that file locally and can optionally publish
the results to GitHub Issues and SecMan. Both publishing paths are explicit opt-ins.

```bash
# 1. local dry run
secman-web-check audit import ~/security-audit-skill/app/run-1/findings.json --output normalized.json
# 2. GitHub issues (private repo; GITHUB_TOKEN needs issues:write), then SecMan
export GITHUB_TOKEN='load-from-your-secret-manager'
secman-web-check audit import findings.json --commit-sha "$(git rev-parse HEAD)" \
  --push-to-github --github-repo OWNER/PRIVATE-REPO \
  --push-to-secman --target https://app.example.com --scanner-id 44
```

## Behavior

- Verdicts: `confirmed` imported; `needs_validation` only with `--include-needs-validation`
  (severity INFO, low confidence, title prefixed); `rejected` never.
- Input is size-bounded (16 MiB, 500 records), fail-closed on malformed records, unsafe file
  paths (absolute or `..`) and invalid fingerprints. `--min-severity` filters confirmed records.
- Attacker payloads, reproduction steps and observed results are excluded unless
  `--include-exploit-detail`. `@mentions` are neutralized; control characters are stripped.
- **GitHub**: refuses public repositories unless `--allow-public-repo`. Issues carry labels
  `security-audit` and `severity:<level>` and a hidden `secman-web-check:audit:<fingerprint>`
  marker, so reruns skip existing issues. `--max-issues` (default 25) bounds creation.
- **SecMan**: submits a REST v1 snapshot through the matched authorized subject for
  `--target`, with `filePath`, `lineRange`, `commitSha` and the GitHub `issueUrl`. The
  scanner ID comes from `--scanner-id` or `SECMAN_AUDIT_SCANNER_ID`; use a registration
  dedicated to code audits. `completeCoverage` is always `false`, so absence never resolves
  older findings. The run key ignores timestamps, so retries are idempotent.
- No raw response bodies are involved; the scanner makes no request to the audited target.

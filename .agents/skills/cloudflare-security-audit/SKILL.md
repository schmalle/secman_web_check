---
name: cloudflare-security-audit
description: Run Cloudflare's security-audit-skill on this repo or another authorized codebase, then import findings.json into GitHub issues and SecMan with `secman-web-check audit import`. Use for source-code security audits and publishing their results.
---

# Cloudflare security audit → GitHub issues + SecMan

Only audit code you are authorized to assess. The audit skill is separate third-party
software: install it yourself (`npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit`)
and read its `SKILL.md`. Do not execute target code without the sandbox it requires.

1. Run the audit. Keep its output outside the repo (default `~/security-audit-skill/<repo>/run-N`)
   unless the directory is git-ignored. It produces `findings.json`.
2. Dry-run the import (no network, no publishing):
   `uv run --locked secman-web-check audit import RUN/findings.json --output normalized.json`
3. Review the table. Only `confirmed` records are imported; add `--include-needs-validation`
   for leads. `rejected` is never imported. Payloads/repro steps are omitted unless
   `--include-exploit-detail` is passed, so keep that off for any shared tracker.
4. Publish only when asked, explicitly:
   - GitHub: `--push-to-github --github-repo OWNER/NAME` with `GITHUB_TOKEN`. Public repos
     are refused unless `--allow-public-repo`. Re-runs are idempotent (hidden fingerprint marker).
   - SecMan: `--push-to-secman --target https://deployed.example --scanner-id N`
     (or `SECMAN_AUDIT_SCANNER_ID`) with the usual `SECMAN_*` credentials. Uploads never resolve
     older findings. GitHub runs first so SecMan findings link to the issues.
5. Report the counts and issue URLs; never print tokens.

Details: `docs/CODE_AUDIT.md`.

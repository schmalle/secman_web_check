# SecMan web-security check

`secman-web-check` is an authorized web-security scanner that will publish normalized
findings to SecMan. Scan only systems you own or are explicitly authorized to assess.

The package foundation provides immutable scan models and configuration loading. CLI
commands, target validation, checks, reporting, persistence, and SecMan upload are
added in subsequent releases.

Configuration values are read in this order: explicit CLI values, `SECMAN_WEB_CHECK_*`
environment variables, a `[scan]` TOML table, then safe defaults. Copy `.env.example`
for local placeholders; keep actual credentials in the environment only.

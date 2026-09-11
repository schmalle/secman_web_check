# SecMan web-security check

`secman-web-check` is an authorized web-security scanner that will publish normalized
findings to SecMan. Scan only systems you own or are explicitly authorized to assess.

The package currently provides immutable scan models, configuration and target policy,
passive HTTP checks, and the version-1 SecMan integration-result client. The client uses
the same subject-discovery and atomic run-submission endpoints as `secman_visual_check`
and `secscan`: `/api/integrations/v1/scanners/{id}/subjects` and
`/api/integrations/v1/runs`. The scanner CLI, reporting, persistence, and upload
orchestration are added in subsequent releases.

Configuration values are read in this order: explicit CLI values, `SECMAN_WEB_CHECK_*`
environment variables, a `[scan]` TOML table, then safe defaults. Copy `.env.example`
for local placeholders; keep actual credentials in the environment only.

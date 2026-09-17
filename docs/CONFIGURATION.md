# Configuration reference

Scanner configuration is resolved in this order: CLI overrides, environment variables,
the `[scan]` table selected with `--config`, then built-in safe defaults.

| TOML key | Environment variable | Default | Constraint |
| --- | --- | ---: | --- |
| `concurrency` | `SECMAN_WEB_CHECK_CONCURRENCY` | `4` | integer >= 1 |
| `active` | `SECMAN_WEB_CHECK_ACTIVE` | `false` | boolean |
| `allow_private_targets` | `SECMAN_WEB_CHECK_ALLOW_PRIVATE_TARGETS` | `false` | boolean |
| `max_body_bytes` | `SECMAN_WEB_CHECK_MAX_BODY_BYTES` | `1048576` | integer >= 1 |
| `max_redirects` | `SECMAN_WEB_CHECK_MAX_REDIRECTS` | `5` | integer >= 0 |
| `connect_timeout_seconds` | `SECMAN_WEB_CHECK_CONNECT_TIMEOUT_SECONDS` | `10.0` | number > 0 |
| `read_timeout_seconds` | `SECMAN_WEB_CHECK_READ_TIMEOUT_SECONDS` | `20.0` | number > 0 |

Unknown keys and fractional values for integer fields are rejected. CLI `--active` and
`--allow-private-targets` are independent opt-ins. Secrets are deliberately excluded
from TOML and CLI arguments.

MariaDB environment variables:

- Required: `SECMAN_WEB_CHECK_DB_HOST`, `SECMAN_WEB_CHECK_DB_USER`,
  `SECMAN_WEB_CHECK_DB_PASSWORD`.
- Optional: `SECMAN_WEB_CHECK_DB_NAME` (default `secman_web_check`),
  `SECMAN_WEB_CHECK_DB_PORT` (default `3306`), and `SECMAN_WEB_CHECK_DB_SSL_CA`.

SecMan environment variables:

- Required: `SECMAN_URL` using HTTPS.
- Scanner IDs: `SECMAN_SECURITY_SCANNER_ID` for security mode and
  `SECMAN_VISUAL_SCANNER_ID` for visual mode. A single-mode run may use the legacy
  `SECMAN_SCANNER_ID`; combined runs deliberately require both mode-specific IDs.
- Authentication: `SECMAN_TOKEN`, or both `SECMAN_USERNAME` and `SECMAN_PASSWORD`.

Visual analysis environment variables:

- `SECMAN_VISION_API_KEY`: required unless `--visual-no-ai` is selected.
- `SECMAN_VISION_MODEL`: optional model slug.
- `SECMAN_VISION_BASE_URL`: optional public HTTPS OpenAI-compatible API base URL.

Load secrets from a secret manager into the process environment. Do not commit a filled
`.env` file or pass secrets as shell arguments.

For Proton Pass, put only `pass://...` references in an environment file and run
`./scripts/scan-with-proton-pass.sh`. The wrapper uses `.env` by default, accepts
`--env-file FILE`, honors `SECMAN_WEB_CHECK_PASS_ENV_FILE`, and can use a custom
`SECMAN_PASS_CLI` executable. It always adds `--push-to-secman`.

For production AWS workloads, store an allowlisted JSON object in Secrets Manager and
run `scripts/scan-with-aws-secrets.py --secret-id NAME -- SCAN_ARGS`. The wrapper uses
the standard AWS CLI credential chain, rejects unknown secret keys, places values only
in the scanner child environment, and always adds `--push-to-secman`.

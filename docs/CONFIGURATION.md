# Configuration reference

Scanner configuration is resolved in this order: CLI overrides, environment variables,
the `[scan]` table selected with `--config`, then built-in safe defaults.

| TOML key | Environment variable | Default | Constraint |
| --- | --- | ---: | --- |
| `concurrency` | `SECMAN_WEB_CHECK_CONCURRENCY` | `20` | integer >= 1 |
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
- Scanner IDs: `SECMAN_SECURITY_SCANNER_ID` for baseline security mode,
  `SECMAN_EXTENDED_SCANNER_ID` for opt-in extended security checks, and
  `SECMAN_VISUAL_SCANNER_ID` for visual mode. A baseline single-mode run may use the legacy
  `SECMAN_SCANNER_ID`; combined runs deliberately require both mode-specific IDs.
- Authentication: `SECMAN_TOKEN`, or both `SECMAN_USERNAME` and `SECMAN_PASSWORD`.

Visual analysis environment variables:

- `SECMAN_VISION_API_KEY`: required unless `--visual-no-ai` is selected.
- `SECMAN_VISION_MODEL`: optional model slug.
- `SECMAN_VISION_BASE_URL`: optional public HTTPS OpenAI-compatible API base URL.
- `--visual-redacted-crops DIR`: required for remote visual analysis; the directory must
  contain operator-reviewed PNG crops named like the local screenshots.

Autonomous check selection requires both `--active` and `--ai-agent`:

- `SECMAN_AI_API_KEY`: OpenRouter key, required for the agent.
- `SECMAN_AI_MODEL`: optional model slug.
- `SECMAN_AI_BASE_URL`: optional HTTPS API base URL.

Crawl limits are CLI options: `--max-pages` (50), `--max-depth` (2), and
`--max-requests` (200). `--api-spec` reads a local OpenAPI JSON document of at most
1 MB and seeds only literal GET paths. `--allowed-origin` is repeatable and grants
additional origins for crawling or visual resources. These options do not change the
default non-crawling scan.

OpenRouter system-review environment variables:

- `OPENROUTER_API_KEY`: required only with `--llm-review`.
- `SECMAN_OPENROUTER_MODEL`: optional model slug (default
  `anthropic/claude-sonnet-4.5`).
- `SECMAN_OPENROUTER_BASE_URL`: optional public HTTPS API base URL (default
  `https://openrouter.ai/api/v1`).

The review system prompt is loaded from the packaged
`src/prompts/system-review.txt`. Pass `--llm-prompt PATH` to use a user-modified UTF-8
prompt. The distribution also includes focused `src/prompts/aws-security-review.txt` and
`src/prompts/secrets-security-review.txt` templates. The default prompt covers supported
AWS and secret-exposure indicators; the focused templates provide stricter review scopes.
An empty or unreadable prompt aborts before scanning. The model receives only
sanitized result metadata, component evidence, deterministic findings, stage errors,
the optional AWS account binding, and JavaScript checksums—not raw HTTP or JavaScript
response bodies. Both
`--llm-review` and `--javascript-inventory` are explicit, independent opt-ins.

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


HTTP requests have a cumulative 60-second deadline across redirects, including socket
connect, TLS negotiation, headers and body reads. `request_timeout_seconds` and
`SECMAN_WEB_CHECK_REQUEST_TIMEOUT_SECONDS` configure it. HTTP requests across a target
share a 300-second budget (`target_timeout_seconds`,
`SECMAN_WEB_CHECK_TARGET_TIMEOUT_SECONDS`), preserved across collector clones and optional
HTTP probes. Expired requests produce incomplete target results; sibling results remain.
The security batch orchestrator additionally isolates each target in a spawned worker
with the same target deadline. On expiry it terminates the worker (and its process group
on POSIX), reports that target as failed/incomplete, and retains completed sibling targets.
This outer deadline includes DNS, TLS, provider and external-tool analysis. Direct
`scan_target` callers and browser interception retain HTTP-operation deadlines; those
in-process calls do not interrupt a blocked operating-system resolver.

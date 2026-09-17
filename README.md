# SecMan web-security check

`secman-web-check` is the merged command-line scanner for two selectable approaches:
bounded HTTP/TLS security checks and headless-browser visual exposure checks. Run
either approach independently or run both against the same explicit target set.

Redirect chains are reported hop by hop. Cross-host transitions and blocked downgrade,
invalid, or over-limit redirects receive distinct findings.

> Scan only systems you own or are explicitly authorized to assess. Passive scanning is
> the default. Active requests and access to RFC1918/ULA targets require separate,
> explicit opt-ins.

## Five-minute quickstart

Prerequisites: macOS or Linux, Python 3.12 or newer, and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone <repository-url> secman_web_check
cd secman_web_check
./scripts/setup.sh
uv run --locked secman-web-check --help
uv run --locked secman-web-check scan https://example.com \
  --format all \
  --output-dir scan-output \
  --fail-on none
```

Replace `https://example.com` with an authorized target. The final command performs a
passive HTTP/TLS scan and writes terminal, JSON, SARIF, and self-contained HTML output.
Machine reports are placed below `scan-output/` and contain findings only—never raw
response bodies.

You can also activate the virtual environment and use the installed command directly:

```bash
source .venv/bin/activate
secman-web-check scan https://example.com
```

## Common examples

Select the scan approach explicitly:

```bash
# HTTP/TLS checks only (the backward-compatible default)
uv run --locked secman-web-check scan https://example.com --scan-mode security

# Browser screenshot plus vision analysis
SECMAN_VISION_API_KEY='load-from-your-secret-manager' \
  uv run --locked secman-web-check scan https://example.com --scan-mode visual

# Security and visual scans in one local report
uv run --locked secman-web-check scan https://example.com \
  --scan-mode both --visual-no-ai --format all --fail-on none
```

`--visual-no-ai` performs deterministic screenshot capture without a model call, so it
cannot report visual-content findings. Screenshots are written below
`OUTPUT_DIR/screenshots` unless `--visual-output-dir` is supplied. Full-page captures
are capped at 4000 pixels.

Scan one public target using safe defaults:

```bash
./scripts/scan-single.sh https://example.com -- --format terminal
```

Verify redirect reporting with the public HTTP testing endpoint:

```bash
uv run --locked secman-web-check scan https://httpbin.org/redirect/1 \
  --format json \
  --fail-on none
```

The JSON findings include `WEB-TRANSPORT-REDIRECT` for the observed hop. Redirects to a
different hostname, HTTPS downgrades, and blocked redirects receive additional rule IDs.

Scan the example target list and write every format:

```bash
./scripts/scan-list.sh examples/targets.txt -- \
  --config examples/config.toml \
  --format all \
  --output-dir scan-output \
  --fail-on medium
```

Run the documented active probe allowlist:

```bash
uv run --locked secman-web-check scan https://example.com --active
```

The `--active` flag enables fixed `TRACE`, `OPTIONS`, `.env`, `.git/HEAD`,
`server-status`, and configuration-backup requests. It does not enable crawling,
arbitrary paths, authentication, exploitation, brute force, or fuzzing.

Scan an authorized private target:

```bash
uv run --locked secman-web-check scan https://10.20.30.40 \
  --allow-private-targets
```

This flag permits only RFC1918 IPv4 and IPv6 ULA addresses. Loopback, link-local,
multicast, unspecified, documentation, and other special-purpose ranges remain denied.
It does not imply `--active`.

## Targets

Supply exactly one positional target, one `--targets-file`, or one `--targets-csv`.
Hostnames without a scheme use HTTPS. Plain target files are UTF-8, one URL or hostname
per line; blank lines and lines beginning with `#` are ignored, and normalized
duplicates are removed.

```bash
secman-web-check scan example.com
secman-web-check scan https://example.com/application/health
secman-web-check scan --targets-file examples/targets.txt
secman-web-check scan --targets-csv testdata/targets-aws.csv
```

AWS target CSV files use this exact header and one account/target pair per row:

```csv
awsAccountNumber,target
111122223333,https://example.com/
444455556666,service.example.org
```

Account numbers must contain exactly 12 digits. The account number is retained in JSON
reports and narrows SecMan subject matching before URI or hostname matching. A normalized
target cannot be assigned to two different accounts in the same file.

User information, URL fragments, non-HTTP schemes, and denied network addresses are
rejected. Every DNS answer and redirect is revalidated. Approved connections pin the
resolved IP while retaining the hostname for HTTP `Host`, TLS SNI, and certificate
verification.

## Reports and exit codes

`--format` is repeatable and accepts `terminal`, `json`, `sarif`, `html`, or `all`.
Terminal is the default. JSON uses schema version `1.0`; SARIF uses version `2.1.0`;
HTML is self-contained, script-free, escaped, and protected by a restrictive CSP.

`--fail-on` accepts `info`, `low`, `medium`, `high`, `critical`, or `none` and defaults
to `high`.

- `0`: scan completed and no finding met the configured threshold.
- `1`: at least one finding met the configured threshold.
- `2`: invalid configuration, a failed/partial target, or an operational adapter error.

See [Report formats](docs/REPORTS.md) for schemas and examples.

## Configuration

Configuration precedence is CLI, `SECMAN_WEB_CHECK_*` environment variables, the
`[scan]` table in a TOML file, then safe defaults. The example config keeps active and
private scanning disabled.

```bash
uv run --locked secman-web-check scan --targets-file examples/targets.txt \
  --config examples/config.toml
```

Secrets are never accepted as CLI values or TOML settings. Vision credentials use
`SECMAN_VISION_API_KEY`; optional `SECMAN_VISION_MODEL` and
`SECMAN_VISION_BASE_URL` select the model/provider. See
[Configuration reference](docs/CONFIGURATION.md).

## Optional MariaDB history

MariaDB access occurs only for `db`, `history`, or a scan with `--store-db`.

```bash
export SECMAN_WEB_CHECK_DB_HOST=db.example.invalid
export SECMAN_WEB_CHECK_DB_USER=scanner_user
export SECMAN_WEB_CHECK_DB_PASSWORD='load-from-your-secret-manager'
export SECMAN_WEB_CHECK_DB_NAME=secman_web_check

uv run --locked secman-web-check db install
uv run --locked secman-web-check db status
uv run --locked secman-web-check scan https://example.com --store-db
uv run --locked secman-web-check history list --limit 20
```

See [MariaDB setup](docs/DATABASE.md) before applying the example grants.

## Optional SecMan upload

Register separate SecMan scanners for independent lifecycle snapshots: source
`WEB_SECURITY` for security results and source `VISUAL` for visual results. Assign the
same authorized subjects where appropriate. A combined run requires both IDs so one
mode can never resolve findings owned by the other.

```bash
export SECMAN_URL=https://secman.example.invalid
export SECMAN_SECURITY_SCANNER_ID=41
export SECMAN_VISUAL_SCANNER_ID=42
export SECMAN_TOKEN='load-from-your-secret-manager'

uv run --locked secman-web-check scan https://example.com --scan-mode both \
  --format json \
  --push-to-secman
```

Uploads use `/api/integrations/v1`, never fall back to legacy ingestion, and submit each
target as an atomic snapshot. Partial or failed coverage never resolves older findings.
See [SecMan integration](docs/SECMAN.md).

To resolve the SecMan credentials with Proton Pass, copy the reference-only example,
replace its item paths, log in once, and use the wrapper. It always enables direct
SecMan upload:

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

Use `--env-file FILE` (or `SECMAN_WEB_CHECK_PASS_ENV_FILE`) for another reference file.
`SECMAN_PASS_CLI` may name a non-default `pass-cli` executable. Resolved secrets remain
in the child process environment and are never added to the scanner command line.
The ready-to-edit CSV used above is stored at `testdata/targets-aws.csv`.

For production on AWS, store the same variables as a JSON object in Secrets Manager
and use the normal AWS credential chain (instance role, task role, or workload
identity). The wrapper allowlists environment keys and never prints the returned
secret:

```bash
./scripts/scan-with-aws-secrets.py \
  --secret-id prod/secman/web-check -- \
  https://example.com --scan-mode both --format json --fail-on none
```

## Development and verification

The repository intentionally keeps Python source files directly under `src/`; the build
maps that directory to the installed `secman_web_check` package.

```bash
./scripts/verify.sh
```

The verification script checks the lockfile, tests, Ruff lint/formatting, strict mypy,
the source distribution, and the wheel. Unit tests use deterministic transports and
mock adapters; they do not require a live target, MariaDB instance, or SecMan deployment.

## Documentation

- [Checks and severities](docs/CHECKS.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Safety and authorization](docs/SAFETY.md)
- [Report formats](docs/REPORTS.md)
- [MariaDB setup](docs/DATABASE.md)
- [SecMan integration](docs/SECMAN.md)

## Limitations

- No crawling, discovery, authentication testing, exploitation, brute force, or
  arbitrary fuzzing. Visual mode executes the selected page in isolated headless
  Chromium with outbound destination checks on every request.
- Active findings use strong bounded signatures but may still require human validation.
- HTTPS targets use SSLyze for the documented TLS capabilities; unavailable individual
  capabilities make the target partial instead of silently clean.
- MariaDB and SecMan behavior is covered with isolated tests here; operators must verify
  connectivity, permissions, TLS trust, and retention policy in their own environment.

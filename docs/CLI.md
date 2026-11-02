# CLI reference

Reference for the implemented `0.3.0` working tree. Run only against authorized systems.
Inside the checkout, prefix the installed command with `uv run --locked`. Python 3.12+
required; `scripts/setup.sh` installs the locked dependencies and matching Chromium.

## Commands

```text
secman-web-check [--help] [--show-completion | --install-completion]
  scan [TARGET] [OPTIONS]
  compare OLD NEW [--json]
  db install
  db status
  history list [--limit INTEGER]
  history export RUN_ID --output report.json
  intel update --output snapshot.json [--package NAME]... [--advisory ID]...
  evaluate CORPUS --output measurements.json
```

Every command/group supports `--help`. There is no `--version`; query the installed
package with `uv run --locked python -c 'from importlib.metadata import version; print(version("secman-web-check"))'`.

## Selecting targets and outputs

Exactly one target source is required:

| Input | Behavior |
| --- | --- |
| Positional `TARGET` | HTTP(S) URL or hostname; HTTPS assumed without scheme |
| `--targets-file PATH` | UTF-8, one target per line; comments/blanks ignored |
| `--targets-csv PATH` | Exact `awsAccountNumber,target` header; 9–12 digit account number; whitespace-separated targets allowed in a cell |
| `--targets-from-secman` | Authorized subjects bound to the selected scanner; requires SecMan configuration |

Duplicates are normalized. Conflicting CSV account bindings fail. Invalid list lines
are skipped with stderr warnings; `--strict` aborts on the first invalid line. Invalid
headers, unreadable files and all-invalid lists abort. URL credentials/fragments,
unsupported schemes and denied addresses are rejected. Quote URLs with shell metacharacters.

| Option | Default | Meaning |
| --- | --- | --- |
| `--strict` | off | Reject invalid target-file/CSV lines immediately |
| `--config PATH` | none | Load TOML `[scan]` settings |
| `--scan-mode security\|visual\|both` | `security` | Select HTTP/TLS, browser capture, or both passes |
| `--concurrency INTEGER` | `20` | Target workers and global concurrent connection admissions, minimum 1 |
| `--format FORMAT`, `-f FORMAT` | `terminal` | Repeatable `terminal`, `json`, `sarif`, `html`, or `all` |
| `--output-dir PATH` | `scan-output` | UUID-named local report files |
| `--fail-on LEVEL` | `high` | `info`, `low`, `medium`, `high`, `critical`, or `none` |
| `--store-db` | off | Store summaries and full JSON archive in MariaDB |
| `--push-to-secman` | off | Upload atomic mode-specific snapshots through REST v1 |

`--format json` writes a JSON file; stdout prints its path, not its contents. Progress
and warnings go to stderr. JSON schema is `1.3`, SARIF is `2.1.0`. Local reports include
the coverage manifest/hash, evidence references, check outcomes, analysis provenance,
script metadata and declared/observed API inventory. Read files for machine processing.

```bash
secman-web-check scan https://example.com --format all --fail-on none
secman-web-check scan --targets-file examples/targets.txt --strict --format json
```

Replace example targets with authorized systems. A default security scan makes bounded
GET requests, including `/.well-known/security.txt`, and TLS certificate/protocol inventory.
It is not passive network observation. TLS vulnerability probes need a separate opt-in.

## Optional security and discovery capabilities

| Option | Default | Meaning |
| --- | --- | --- |
| `--active` | off | Fixed HTTP method/exposure/open-redirect probes |
| `--tls-vulnerabilities` | off | SSLyze vulnerability probes beyond certificate/protocol inventory |
| `--allow-private-targets` | off | RFC1918 IPv4 / IPv6 ULA only; never loopback or link-local |
| `--dirbuster` | off | Fixed non-recursive path discovery after final HTTP 200 |
| `--external-scanner NAME` | none | Repeatable `nuclei` or `nikto`; requires pinned profile and supported containment |
| `--external-profile PATH` | none | Reviewed external binary/template/database manifest |
| `--external-profile-sha256 HEX` | none | Trusted SHA-256 of that manifest |
| `--javascript-inventory` | off | Fetch referenced script assets; retain sanitized URL, checksum, bytes/status/truncation |
| `--crawl` | off | Bounded public GET discovery from HTML, form actions, robots and sitemaps |
| `--browser-discovery` | off | Execute page JS in isolated Chromium; follow rendered anchors and inventory observed fetch/XHR |
| `--allowed-origin URL` | none | Repeatable extra crawl/browser/script origin; no path or query |
| `--max-pages INTEGER` | `50` | At least 1; maximum HTML/browser discovery pages |
| `--max-depth INTEGER` | `2` | At least 0; link depth |
| `--max-requests INTEGER` | `200` | At least 1; crawl and security collector request budget when crawling |
| `--api-spec PATH` | none | With `--crawl`, bounded local OpenAPI JSON; metadata inventory and literal GET seeds |
| `--advisory-db PATH` | none | Maintained offline OSV snapshot |
| `--advisory-sha256 HEX` | none | Trusted SHA-256 of that snapshot; mandatory with `--advisory-db` |

Switches are independent. `--active` enables neither TLS vulnerability probes nor
crawling, JavaScript collection, external tools or browser discovery. Browser discovery
blocks non-GET/HEAD requests, cookies/session replay and off-scope traffic; it writes no
screenshots. It follows rendered anchors without clicking arbitrary controls. Blocked
fetch/XHR write attempts are inventory-only with `executed=false`.

OpenAPI inventory records methods (including unexecuted mutations), placeholders,
parameter names/types, content types and declared authentication. It excludes examples,
defaults, credentials and parameter values. Only literal GET paths become crawl seeds;
placeholders are not populated and writes are not executed. External `$ref` resolution
is not permitted. OpenAPI server declarations do not grant target scope.

JavaScript inventory is not source analysis or a dependency SBOM. Truncated checksums
cover only collected bytes. Script requests and redirects stay on the page origin or an
explicit `--allowed-origin`; unapproved script origins leave inventory incomplete. Combined mode preserves this inventory. Raw HTTP/JS bodies
remain transient and are not report/storage artifacts.

```bash
secman-web-check scan https://example.com --crawl --browser-discovery \
  --api-spec ./openapi.json --max-pages 20 --max-depth 2 \
  --format json --fail-on none
```

## Shared traffic budgets

The same controller spans security workers, visual workers, browser interception,
provider calls and external proxy connections. Defaults can be overridden in TOML or
`SECMAN_WEB_CHECK_*` environment variables as well as the following CLI options:

| Option | Default | Meaning |
| --- | ---: | --- |
| `--requests-per-second NUMBER` | `1` | Maximum admission rate per origin |
| `--global-requests-per-second NUMBER` | `20` | Maximum admission rate across origins |
| `--per-origin-concurrency INTEGER` | `1` | Concurrent admitted connections per origin |
| `--max-operations INTEGER` | `10000` | Run-wide admission ceiling |
| `--max-provider-calls INTEGER` | `50` | Shared call ceiling across all AI features |

HTTP redirects consume individual admissions. SSLyze obtains admission for each TCP
connection, which also revalidates DNS; its TLS messages within one connection are not
separate HTTP requests. Provider calls consume one admission/call. External HTTPS uses
bounded CONNECT tunnels plus the pinned tool's native pacing; encrypted requests within
one tunnel cannot be counted individually by the proxy. Budgets are admission/connection
bounds, not a claim to count every protocol message. Native output/tunnel byte and time
limits apply separately. Each AI call also has a bounded output-token allowance; there
is no currency-based provider cost estimate.

Target workers have hard deadlines. Cancellation stops admission, reclaims dead-worker
leases and marks unfinished targets incomplete while retaining completed results.
See [CONFIGURATION.md](CONFIGURATION.md) for socket/request/target deadlines.

## External engine profiles

Tag-only execution is no longer supported. An external run requires an explicitly
authorized origin-root target (no application path/query), checksum-pinned binary/assets,
read-only review assertion, tested version label, and a checksum-pinned profile. The
child receives a scope proxy as its only permitted network destination. The proxy
revalidates DNS and pins the approved endpoint. Cross-origin requests/tunnels are denied.

Containment currently uses native macOS `sandbox-exec`. Unsupported platforms or denied
sandbox setup fail closed; there is no unrestricted fallback. Nuclei uses only the
selected pinned templates, with redirects, interactions, updates and raw output disabled.
Nikto uses pinned assets and fixed non-destructive tuning. Output is resource-limited
before parsing. Native tool compatibility must be checked for the pinned installation;
the native containment fixture itself uses curl, not a full Nuclei/Nikto distribution.

Profile shape (replace placeholders only after reviewing actual assets):

```json
{
  "version": 1,
  "engines": {
    "nuclei": {
      "path": "/absolute/path/to/nuclei",
      "sha256": "<binary SHA-256>",
      "version": "<tested version>",
      "reviewedReadOnly": true,
      "assets": [{"path": "/absolute/path/to/reviewed-template.yaml", "sha256": "<template SHA-256>"}]
    }
  }
}
```

```bash
secman-web-check scan https://example.com/ --external-scanner nuclei \
  --external-profile ./reviewed-profile.json --external-profile-sha256 "$PROFILE_SHA256"
```

The profile is an explicit trust decision about those exact assets. Do not label an
unreviewed template or plugin read-only merely to enable execution.

## Maintained vulnerability intelligence

Updates are explicit and separate from scans. Package queries discover new advisories
for supported npm libraries, while advisory IDs select exact OSV records. No detected
asset inventory is uploaded. A snapshot replaces its predecessor atomically only after
bounded download, normalization and validation.

```bash
secman-web-check intel update --package jquery --package lodash --output ./advisories.json
# Keep the printed SHA-256 in trusted configuration alongside the snapshot.
secman-web-check scan https://example.com --advisory-db ./advisories.json \
  --advisory-sha256 "$ADVISORY_SHA256" --format json
```

`--package` and `--advisory` are repeatable; at least one is required. Supported npm
names: `jquery`, `react`, `vue`, `angular`, `lodash`, `moment`, `d3`, `bootstrap`,
`tailwindcss`, `bulma`, `foundation-sites`, `materialize-css`. Updates allow at most
500 advisories and bounded pagination. Only supported SEMVER ranges and explicit
versions are matched; withdrawn records do not match. Sources, snapshot hash, timestamp,
freshness and unsupported-range counts enter the manifest. Snapshots older than 30 days
mark a scan incomplete. An operator can schedule the explicit update command externally.

The checksum protects the chosen artifact; it is not an upstream digital signature.
Updates use verified HTTPS to OSV. Without a snapshot, the small bundled legacy catalogue
remains available offline, explicitly labeled as having unverified freshness.

## AI selection, evidence review and visual mode

| Option | Default | Meaning |
| --- | --- | --- |
| `--ai-agent` | off | With effective active configuration, sequence only approved HTTP probe IDs |
| `--llm-review` | off | Review typed evidence references after scanning |
| `--llm-prompt PATH` | packaged system prompt | Readable, non-empty UTF-8 prompt file, at most 64 KiB |
| `--visual-no-ai` | off | Local screenshot capture without provider analysis |
| `--visual-output-dir PATH` | `OUTPUT_DIR/screenshots` | Local screenshot directory |
| `--visual-redacted-crops PATH` | none | Operator-reviewed PNG crops matching screenshot filenames |

AI selection uses `SECMAN_AI_API_KEY`; review uses `OPENROUTER_API_KEY`; vision uses
`SECMAN_VISION_API_KEY`. Model/base-URL overrides are in [CONFIGURATION.md](CONFIGURATION.md).
All use strict schemas, bounded pinned provider calls and the same requested retention
policy. These requests still require provider-side policy verification.

Review can select only known evidence IDs and fixed categories. It cannot write free
text, unsupported severities or invented evidence into findings. Observations use INFO
and `validationStatus=needs-review`, with model, prompt hash and policy attribution.
Different same-category evidence sets have different identities. Provider failure is
recorded per target; completed deterministic evidence and earlier reviewed results survive.
Reports, archives and the primary mode's non-terminal SecMan snapshot receive the same
review observations. Model/agent absence never proves resolution.

Visual mode requires Chromium. It captures HTTP 200 pages only, caps PNG height at 4000
pixels, and uses separate operator-reviewed crops for remote analysis. Local screenshots
can contain sensitive visible information; operators own their retention. Raw captures
are not sent to providers. Screenshot-only results can succeed with `complete=false`.
Combined runs preserve inventory and retain separate SecMan snapshots.

```bash
secman-web-check scan https://example.com --scan-mode visual --visual-no-ai
secman-web-check scan https://example.com --scan-mode both --visual-no-ai --format all
secman-web-check scan https://example.com --javascript-inventory --llm-review \
  --llm-prompt src/prompts/aws-security-review.txt --format json
```

AWS prompts do not obtain AWS control-plane evidence. Checksums do not reveal secrets
inside source. Authentication, mutation, fuzzing and business-logic testing remain outside
this tool's public-surface scope.

## Configuration, integration and exit behavior

Generic precedence is explicit CLI > `SECMAN_WEB_CHECK_*` environment > TOML `[scan]`
> defaults, for `ScannerConfig` fields only. Crawl/report/provider options are not generic
TOML keys. Timeout/body/redirect fields are configured through environment/TOML.
Positive flags set true only: omitting `--active`, `--tls-vulnerabilities` or
`--allow-private-targets` does not disable an environment/TOML true value. No negative
switches are implemented; use controlled false environment values for a default profile.

Exactly one target source is required. Security extensions require `security` or `both`.
`--api-spec` requires `--crawl`; additional origins require crawling, browser discovery, script inventory
or visual mode. `--ai-agent` requires effective active configuration. A prompt path alone
does not enable review, and visual options alone do not select visual mode.

SecMan requires HTTPS `SECMAN_URL`, a token or username/password, and applicable IDs:
`SECMAN_SECURITY_SCANNER_ID` for baseline, `SECMAN_EXTENDED_SCANNER_ID` for any selected
extended security/JS/review/browser/TLS-vulnerability capability, and
`SECMAN_VISUAL_SCANNER_ID` for visual mode. Single baseline or visual runs can fall back
to `SECMAN_SCANNER_ID`; extended cannot. Combined runs require the two specific IDs.
Baseline uploads remain non-terminal unless `SECMAN_BASELINE_PROFILE_SHA256` explicitly
approves the exact report profile hash; query-bearing, redirected and non-200 contexts remain non-terminal even
then. Review the catalogue, scope and limits before approving a changed hash.
See [SECMAN.md](SECMAN.md). Database setup/credentials are in [DATABASE.md](DATABASE.md).
`history list --limit` defaults to 50 (range 1–500). `history export` preserves the full
schema 1.3 archive; pre-archive history fails explicitly rather than fabricating missing data.

`compare OLD NEW --json` reports introduced, unchanged, resolved and unconfirmed absent
IDs. Resolution requires a matching validated manifest/hash, complete successful passive
coverage, and an executed check domain. Unsupported/skipped checks, query-bearing inputs,
model observations, variable agents and legacy manifests cannot confirm absence.
Comparison exits 0 for a valid comparison; it is not a severity gate.

| Scan exit | Meaning |
| --- | --- |
| `0` | No operational failure and no finding meets the selected threshold |
| `1` | A finding meets `--fail-on` |
| `2` | Invalid configuration, partial/failed target, or handled adapter failure |

Operational failure takes precedence. `--fail-on none` disables only severity gating.
Zero does not assert comprehensive security. Report files can exist even if database or
upload fails. Review failures preserve scan artifacts. Unexpected exceptions/signals are
outside the handled exit contract.

## Detection measurements and wrappers

```bash
secman-web-check evaluate tests/fixtures/detection.json --output measurements.json
```

Evaluation performs no network requests. Each class needs positive and safe fixtures;
output records corpus/evaluator revisions, TP/FP/FN/TN and class precision/recall. Any
false positive or missed fixture exits 1. Results characterize this synthetic corpus,
not real-world coverage. See [EVALUATION.md](EVALUATION.md).

`scan-single.sh TARGET [-- OPTIONS...]` and `scan-list.sh FILE [-- OPTIONS...]` invoke
scans from the repository directory. Use absolute paths for outside files. The Proton
wrapper accepts `--env-file`, resolves `pass://` references, and always adds upload.
The AWS wrapper accepts `--secret-id`, optional `--region`, and scan arguments after `--`;
its allowlist includes all three AI credential families. Secret values are environment-only.
Use the direct CLI for local-only work. `install-db.sh` mutates schema; `verify.sh` runs
local checks and builds packages.

If a browser build is missing, run `uv run --locked python -m playwright install chromium`.
Use the same `PLAYWRIGHT_BROWSERS_PATH` for installation, scanning and tests. Investigate
exit 2 via stderr and JSON errors/execution states; never bypass address/TLS policy to
make a failed collection appear complete.

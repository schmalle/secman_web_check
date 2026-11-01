# Safety and authorization

The scanner is intended only for systems the operator owns or is explicitly authorized
to assess. Every initial URL comes from the command line, a supplied target file, or an
authorized SecMan subject. `--crawl` is required to follow links from that initial URL.

## Default passive behavior

Without `--active`, each target receives a bounded `GET` plus a bounded request to
`/.well-known/security.txt`. HTTPS targets also receive bounded certificate/protocol TLS inventory. Heartbleed,
ROBOT, CCS injection, renegotiation and fallback probes require `--tls-vulnerabilities`;
`--active` independently controls HTTP probes.
The HTTP collector:

- accepts only HTTP and HTTPS URLs without credentials or fragments;
- validates every DNS answer against explicit address policy;
- pins an approved IP while retaining hostname-based Host, SNI, and certificate checks;
- repeats normalization, DNS validation, and address validation for every redirect;
- records sanitized redirect hops and cross-host boundaries as normalized findings;
- blocks HTTPS-to-HTTP downgrade traversal;
- disables environment proxies, cookies, authentication, decompression, and retries;
- bounds redirects, headers, body bytes, timeouts, and concurrency; and
- redacts credentials, cookie values, and query values from retained evidence/errors.

Raw response bodies exist only transiently in bounded memory for rule evaluation. They
are never written to reports, MariaDB, SecMan, or logs.

## Requests enabled by `--active`

| Method | Path | Purpose | Finding requires |
| --- | --- | --- | --- |
| `TRACE` | `/` | TRACE reflection | synthetic Origin value reflected in body |
| `OPTIONS` | `/` | advertised methods | `Allow` includes PUT, DELETE, or PATCH |
| `GET` | `/.env` | environment exposure | at least two fixed secret/config variable signatures |
| `GET` | `/.git/HEAD` | Git metadata exposure | valid `ref: refs/...` body shape |
| `GET` | `/server-status` | operational status exposure | paired server-version and uptime signatures |
| `GET` | `/wp-config.php.bak` | configuration backup | PHP plus DB name/password signatures |
| `GET` | `/?next=https%3A%2F%2Fscanner.invalid%2F` | open redirect | response redirects to the inert canary origin; the scanner does not follow it |

All active requests reuse the same address, redirect, TLS, header, body, and timeout
controls as passive collection. Operators cannot supply arbitrary active paths, methods,
headers, or payloads.
If the initial target redirects to another origin, the scanner skips active probes,
content discovery, external adapters, and AI-selected actions for that target.

## Private targets

`--allow-private-targets` permits authorized RFC1918 IPv4 and IPv6 ULA destinations.
It never permits loopback, link-local, multicast, unspecified, documentation, or other
special-purpose ranges, and it does not enable active probes.

## Visual browser boundary

Visual mode starts a fresh headless Chromium context. HTTP(S) browser requests are
intercepted and fulfilled by the pinned HTTP collector, which validates every DNS
answer and redirect before connection. Requests outside the selected origin and explicit
`--allowed-origin` entries are blocked. Media, WebSocket, and non-GET/HEAD requests are
blocked; `data:` and `blob:` resources generated inside the selected page remain
available. Screenshots are capped at 4000 pixels in height.

Vision analysis sends only an operator-reviewed PNG crop from
`--visual-redacted-crops`; it rejects an identical copy of the raw screenshot. It sends
the origin and HTTP status, not raw page text, title, URL query, or raw screenshot. Use
`--visual-no-ai` when no reviewed crop is available. The credential is read only from
the process environment. The operator is responsible for checking that a supplied crop
is properly redacted.

## Prohibited behavior

The tool does not enumerate ports, discover hosts, authenticate, replay cookies,
brute-force, exploit, upload payloads, or fuzz arbitrary inputs. Optional crawling is
limited to public GET links, bounded depth, page count, and request count.
Do not modify it to bypass target policy or TLS verification for operational scans.

## Optional extended checks

Content discovery and external scanner adapters are separate explicit opt-ins. Content
discovery is bounded to fixed validated relative paths. External scans require reviewed,
checksum-pinned binary/template/database assets and an explicit origin-root target.
Tag-based trust has been replaced by exact assets and supported native containment.
Children can reach only a scope proxy, which validates/pins the destination; Nuclei has
updates/interactions/redirects/raw output disabled and Nikto uses fixed safe tuning.
Missing containment or unsafe/invalid profiles fail closed. The native containment
fixture is documented in EVALUATION.md; real engine-version compatibility remains an
installation-specific requirement.


## Shared budgets, external containment and evidence

One run/origin controller admits HTTP hops, TLS TCP sockets, browser requests and
provider calls across spawned target workers. It bounds concurrent admissions, rates,
operations and provider calls, with cancellation and hard worker deadlines. External
CONNECT tunnels are connection-level admissions with additional byte/time/native-rate
bounds; encrypted requests within a tunnel are not individually counted. See CLI.md.

External engines now require a checksum-pinned reviewed manifest, copied/verified assets,
an explicitly authorized origin-root input and supported native macOS confinement.
Children have only the scope proxy as permitted network egress; the proxy validates every
new destination and denies other origins. Direct egress and user-home reads are denied;
output writes are restricted to a temporary directory and capped before parsing. No
unrestricted fallback exists on unsupported platforms. Pinning is not a substitute for
reviewing the exact templates/plugins as read-only.

URLs cross producer/serialization boundaries without userinfo/query/fragment. Review
providers receive typed observation IDs, not raw page/model text. Findings and analysis
stages retain evidence, model, prompt-hash and policy attribution. Strict review schemas
reject invented evidence and arbitrary text; visual schemas reject unknown/malformed
categories. All AI paths request the same retention policy and have bounded payloads.
No claim of provider-side deletion is inferred from a request flag.

The full normalized JSON archive contains derived records only. Browser discovery does
not write screenshots, replay sessions, click arbitrary controls or execute writes.
Observed blocked write operations are marked inventory-only. Declared API operations
are never executed merely because a method or parameter appears in a schema.

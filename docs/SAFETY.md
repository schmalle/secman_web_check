# Safety and authorization

The scanner is intended only for systems the operator owns or is explicitly authorized
to assess. Every initial URL comes from the command line, a supplied target file, or an
authorized SecMan subject. `--crawl` is required to follow links from that initial URL.

## Default passive behavior

Without `--active`, each target receives a bounded `GET` plus a bounded request to
`/.well-known/security.txt`. HTTPS targets also receive bounded TLS capability checks.
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
discovery is bounded to at most 100 validated relative paths and is neither recursive nor
fuzzed. Nuclei is limited to technology, misconfiguration, and exposure templates with
DoS/fuzz/intrusive tags excluded. Nikto uses the non-destructive tuning classes. Both
adapters use one worker, a low request rate or bounded runtime, no interactive features,
and ephemeral output.

Immediately before each external process, DNS is revalidated against the normal address
policy. The process receives an approved IP literal as its network target and receives
the original hostname only as HTTP Host / virtual-host and TLS SNI metadata. Private
targets still require `--allow-private-targets`.

# Safety and authorization

The scanner is intended only for systems the operator owns or is explicitly authorized
to assess. It does not discover targets: every initial URL comes from the command line or
the supplied target file.

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

All active requests reuse the same address, redirect, TLS, header, body, and timeout
controls as passive collection. Operators cannot supply arbitrary active paths, methods,
headers, or payloads.

## Private targets

`--allow-private-targets` permits authorized RFC1918 IPv4 and IPv6 ULA destinations.
It never permits loopback, link-local, multicast, unspecified, documentation, or other
special-purpose ranges, and it does not enable active probes.

## Visual browser boundary

Visual mode starts a fresh headless Chromium context and applies the same address
policy to the initial page, redirects, frames, and subresources. Media and WebSocket
requests are disabled; `data:` and `blob:` resources generated inside the selected
page remain available. The final navigation address is checked again before page text
or a screenshot is retained. Screenshots are capped at 4000 pixels in height.

Vision analysis is optional and sends the screenshot plus a bounded page-text excerpt
to the configured public HTTPS provider. The provider credential is read only from the
process environment. Select `--visual-no-ai` when page content must not leave the
scanner host.

## Prohibited behavior

The tool does not crawl, enumerate ports, discover hosts, authenticate, replay cookies,
brute-force, exploit, upload payloads, or fuzz arbitrary inputs. Visual mode executes
only the explicitly selected pages and their policy-approved resources.
Do not modify it to bypass target policy or TLS verification for operational scans.

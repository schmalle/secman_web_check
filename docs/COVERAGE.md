# Coverage matrix

This matrix distinguishes implemented checks from categories that need other
authorization or evidence. It is not a claim of complete WSTG, ASVS, or API Top 10
coverage. Rule IDs and exact severity are in [CHECKS.md](CHECKS.md).

| Area | Current coverage | Boundary |
| --- | --- | --- |
| HTTP transport and TLS | Redirects, downgrade signals, certificate and protocol checks | Explicit initial targets |
| Browser headers and cookies | CSP, HSTS, framing, MIME, CORS, cookie attributes | Passive response evidence |
| Public content | Error disclosures, directory listings, forms, mixed content, security.txt | Bounded transient evidence; explicit rule outcomes |
| Public site discovery | Opt-in HTML link crawl and literal OpenAPI GET paths | Origin allowlist, depth, page and request limits |
| Public API behavior | Generic HTTP/header/content checks on discovered GET paths | No parameter mutation or object authorization claims |
| Exposed files and methods | Reviewed active probe catalogue; optional safe Nuclei/Nikto profiles | Explicit flags; no arbitrary payloads |
| Components | Best-effort JS/CSS/server fingerprints and bundled fallback or maintained checksum-pinned OSV snapshot | Unknown versions make no vulnerability claim |
| AI agent | Approved probe sequencing with deterministic matching | `--active --ai-agent`; no raw page content sent |
| Visual analysis | Local screenshot; optional operator-redacted crop to OpenRouter | Human validation of model observations |
| Rendered discovery and API inventory | Opt-in rendered anchors, read-only XHR/fetch metadata, OpenAPI methods/parameters | No writes, example values, session replay or remote schema resolution |
| Authentication, authorization, session workflow | Untested | No credentials or authenticated sessions accepted |
| Injection, business logic, state-changing API behavior | Untested | No generated payloads, write requests, or workflow replay |

Future check-catalogue additions should state their WSTG/ASVS/API category, exact
request shape, safety class, expected proof, false-positive conditions, severity, and
tests before being enabled. A missing category is reported as untested, never clean.

## Remaining work for broader scanner coverage

The [architecture review and capability assessment](ARCHITECTURE_REVIEW.md) records
current implementation inconsistencies, comparison with primary standards/tool
documentation, and a prioritized roadmap with acceptance criteria.

The current implementation is a bounded public-surface scanner. Broader coverage needs
separate, reviewable work with explicit authorization and test fixtures:

1. Extend rendered-anchor/read-only API discovery to additional application states with
   explicit interaction contracts. Current scope blocks writes and session replay.
2. Expand deterministic vulnerability classes only with request contracts, positive and
   safe fixtures, and false-positive review. Injection/OAST remain separate authorization.
3. Treat authenticated and role-comparison profiles as a separate product decision with
   credential/session isolation, not an implicit extension of current flags.
4. Broaden maintained ecosystem/detector support and update provenance beyond the current
   supported npm SEMVER snapshots. Keep unknown versions and unsupported ranges unclaimed.
5. Benchmark the implemented shared limits/cancellation on representative production-sized
   batches and provider budgets; synthetic coordination tests do not measure that throughput.
6. Rehearse SecMan/MariaDB lifecycle behavior on disposable integration data. Validate
   deployment-specific permissions, approved profile hashes, connectivity and retention.


The response-signature corpus measures 20 synthetic positive/safe fixtures across ten
classes. Results and their limits are in [EVALUATION.md](EVALUATION.md). An executed-negative
check is distinguished from unsupported, skipped, failed and budget-exhausted evidence.
The remaining-work list above records broader directions; current remediation and
implemented discovery/intelligence/traffic capabilities are in [IMPLEMENTATION.md](IMPLEMENTATION.md).

# Coverage matrix

This matrix distinguishes implemented checks from categories that need other
authorization or evidence. It is not a claim of complete WSTG, ASVS, or API Top 10
coverage. Rule IDs and exact severity are in [CHECKS.md](CHECKS.md).

| Area | Current coverage | Boundary |
| --- | --- | --- |
| HTTP transport and TLS | Redirects, downgrade signals, certificate and protocol checks | Explicit initial targets |
| Browser headers and cookies | CSP, HSTS, framing, MIME, CORS, cookie attributes | Passive response evidence |
| Public content | Error disclosures, directory listings, forms, mixed content, security.txt | Bounded body evidence |
| Public site discovery | Opt-in HTML link crawl and literal OpenAPI GET paths | Origin allowlist, depth, page and request limits |
| Public API behavior | Generic HTTP/header/content checks on discovered GET paths | No parameter mutation or object authorization claims |
| Exposed files and methods | Reviewed active probe catalogue; optional safe Nuclei/Nikto profiles | Explicit flags; no arbitrary payloads |
| Components | Best-effort JS/CSS/server fingerprints and small offline advisory list | Unknown versions make no vulnerability claim |
| AI agent | Approved probe sequencing with deterministic matching | `--active --ai-agent`; no raw page content sent |
| Visual analysis | Local screenshot; optional operator-redacted crop to OpenRouter | Human validation of model observations |
| Authentication, authorization, session workflow | Untested | No credentials or authenticated sessions accepted |
| Injection, business logic, state-changing API behavior | Untested | No generated payloads, write requests, or workflow replay |

Future check-catalogue additions should state their WSTG/ASVS/API category, exact
request shape, safety class, expected proof, false-positive conditions, severity, and
tests before being enabled. A missing category is reported as untested, never clean.

## Remaining work for broader scanner coverage

The current implementation is a bounded public-surface scanner. Broader coverage needs
separate, reviewable work with explicit authorization and test fixtures:

1. Discover browser-rendered routes and API parameters without executing write actions.
   Verify scope, deduplication, depth and request limits in browser integration tests.
2. Expand the deterministic check catalogue by vulnerability class. Each new probe
   needs an exact request contract, positive and negative fixtures, and a false-positive
   review before the AI agent can select it.
3. Add authenticated and role-comparison profiles only with explicit credential and
   session-handling controls. Verify that secrets are neither sent to OpenRouter nor
   retained in reports or storage.
4. Replace the small bundled component advisory list with a provenance-tracked,
   periodically updated source and version-range tests. Keep unknown versions unclaimed.
5. Add shared origin pacing and cancellation across concurrent targets and external
   adapters, plus measured provider spend and operational metrics. Verify that stopping
   or exhausting any budget leaves coverage incomplete.
6. Rehearse SecMan lifecycle behavior on disposable integration data before treating
   any broader profile as complete coverage. Confirm that absent findings from partial,
   visual, and variable-agent runs never resolve existing issues.

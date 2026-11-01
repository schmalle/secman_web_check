# Architecture review and capability assessment

Reviewed: 2026-10-20. Scope: the `0.3.0` working tree on `dev`, based on commit `329dffa`
plus existing pending changes, including JavaScript inventory and system review.
This is a source-based architecture/capability review with local verification, not a
full vulnerability audit or a production-readiness certification. Scanner behavior
was not changed as part of this review.

## Implementation follow-up

R1–R9 were implemented after this assessment. The finding descriptions below are the
historical evidence that motivated the changes, not a description of the current tree.
See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the fix/verification matrix and remaining
operator-specific validation, and [EVALUATION.md](EVALUATION.md) for measured fixtures.

## Assessment

The tool has a useful foundation for repeatable public-surface assessment: centralized
IP-pinned HTTP collection, explicit opt-ins, bounded requests, deterministic rules,
isolated security workers, normalized output, and conservative SecMan lifecycle handling.
Its principal weakness is incomplete consistency across analysis and output paths.
Adding more probes before correcting privacy, result preservation and coverage identity
would make its reports harder to trust.

It is not yet a state-of-the-art general web application scanner. The main missing
capabilities are browser-driven attack-surface discovery, maintained vulnerability
intelligence, measured detection quality, richer API testing, and operational controls
shared across all execution paths. Authenticated testing, role comparison, injection
and business logic are deliberately outside the current product boundary.

A strong public-surface tool is a coherent goal without those intrusive features.
General authenticated DAST would require a separate authorization and execution model;
it should not be implied by the current `--active` switch or by an LLM integration.

## What works well architecturally

- **One HTTP policy path.** `targets.py` and `http.py` centralize URL/address policy,
  DNS answer validation, approved-IP dialing, SNI, redirect decisions and deadlines.
  Browser requests are fulfilled through that path instead of unrestricted browser HTTP.
- **Simple core contracts.** Immutable models separate transient collection evidence
  from findings, inventory and output. Pure passive checks are easy to fixture-test.
- **Bounded security workers.** `orchestrator.py` isolates a target in a spawned process
  and retains sibling results when a target fails or exceeds its deadline.
- **Explicit integrations.** Local scans need no database, model provider or SecMan.
  Active probes, crawling, private destinations and external tools are opt-ins.
- **Conservative result lifecycle.** Partial coverage is represented explicitly;
  extended and visual uploads cannot silently clear baseline findings. Subject binding
  avoids guessing asset identity from hostname alone.
- **Useful output foundation.** Atomic local reports, SARIF, a script-free HTML report,
  stable finding IDs and JSON comparison support automation without a hosted service.

## Prioritized architecture findings

Priorities here are engineering order, not CVSS ratings: P1 affects privacy or trust in
results, P2 affects fidelity/operability, P3 is a later capability improvement.
References identify functions so the review remains navigable as line numbers change.

### R1: URL sanitization is inconsistent

**Priority: P1. Confirmed with synthetic offline data.**

`javascript.inventory_javascript` stores `script.url` directly. JSON serialization in
`reports/json_report.py::_javascript_document` also passes it through. A script URL such
as `https://example.com/app.js?token=SYNTHETIC` therefore retains its query in the
artifact. `system_review._evidence` passes `target.target.url` directly and also includes
those script URLs in provider evidence. A query-bearing initial target can consequently
reach the provider unchanged when review is enabled. This contradicts broad claims
that all retained/provider evidence is query-redacted.

The exposure and finding serializers already have sanitization helpers; the new paths
do not consistently use them. No raw HTTP body needs to be persisted for this to matter.

**Acceptance:** centralize public-location projection at producer and serialization
boundaries; test credential-like queries in initial, redirect and script URLs across
every report/provider payload. Preserve the real URL only for authorized transient
requests. Add a regression fixture that asserts the synthetic token is absent from
serialized output and mocked provider requests.

### R2: Combined mode drops script inventory

**Priority: P1 for inventory correctness. Confirmed offline.**

`visual.merge_runs` reconstructs `TargetResult` without `javascript_assets`, resetting
the field to its empty default. A security result containing one script becomes a
combined result containing zero scripts. Combined reports and subsequent system review
therefore lose data collected with an explicit user option.

**Acceptance:** preserve security script metadata in merging and test security-only,
visual-only and combined JSON output with a non-empty inventory. Check all other model
fields whenever adding fields or reconstructing results.

### R3: System review is outside the durable result flow

**Priority: P1 for output consistency; P2 for failure isolation. Confirmed by source.**

`cli.scan` assigns `run = review_run(run, ...)`, then writes/stores that replacement.
Uploads still use the original `security_run` and `visual_run`. Thus a model finding
can affect local reports and the exit threshold while being absent from SecMan.

Review runs before local report writing. A provider error aborts without saving completed
deterministic results. Review requests run serially after security workers have finished;
their HTTPX operation timeout is not the security worker's cumulative target deadline.
`ScanRun` completion timestamps also remain the pre-review values.

**Acceptance:** define an explicit analysis-stage/result contract. Preserve deterministic
artifacts on review failure, record review status/timing independently, and specify which
snapshot contains advisory findings. Test provider failure on the second of multiple
targets and compare local, stored and uploaded results. Keep model observations outside
automatic resolution until their lifecycle and human-review policy are defined.

### R4: Profiles do not fully describe coverage

**Priority: P1. False model-finding resolution confirmed offline.**

`orchestrator.scan_all` records active/crawl/dirbuster/external/agent flags in a profile
string, but omits JavaScript inventory, review settings, exact external tools/templates,
limits, scope and catalogue revisions. `review_run` does not change the profile.
`reports.compare.compare_reports` treats any missing finding as resolved when profiles
both equal `security:passive` and the new target is successful/complete. A model finding
from one reviewed run can therefore be called resolved by a later run that did not run
the model at all. CLI extended-scanner selection also omits JS and review settings.

**Acceptance:** record a versioned coverage manifest and deterministic profile hash,
including enabled engines, scope, rule/advisory/template versions and relevant limits.
Compare absence only within the same check/evidence domain. Treat model and variable
agent absences as unconfirmed. Include profile mismatch fixtures and tests of scanner-ID
selection. Distinguish skipped, unsupported, budget-exhausted and executed-negative checks.

### R5: Global traffic limits are not enforced across engines

**Priority: P1 before large target batches. Confirmed by source; load not benchmarked.**

`RequestBudget` is created per security target; visual capture creates another per-target
budget. Separate targets on the same origin can each consume their own pace allowance.
TLS, provider calls and external-tool traffic are not counted in that budget.
`tls._SCAN_GATE` is module-level process-local state: with spawned per-target workers,
its advertised process-wide ceiling does not limit the overall security batch.

Visual navigation has its own timeout, but it does not run behind the security worker's
outer target process deadline. Provider analysis also has separate scheduling. The CLI's
`--concurrency` is therefore not a universal limit on network connections or model calls.

**Acceptance:** establish run-wide/per-origin admission and cancellation contracts for
HTTP, TLS, browser, provider and external engines. Measure repeated-origin load with
concurrent targets; assert peak connections and requests/second, not just config values.
Budget exhaustion/cancellation must leave incomplete coverage and preserve finished work.

### R6: External execution needs stronger reproducibility and containment

**Priority: P1 before treating external profiles as proven non-invasive.**

`external_scanners.py` passes a freshly approved IP and hostname metadata to optional
executables. This is a useful boundary, but execution does not pass through the shared
collector or a network sandbox. Nuclei template selection is tag-based and depends on
the operator's installed binary/template set; no exact template manifest is pinned.
Both adapters target the origin root, discarding an input application path. A scan of
`https://example.com/app/` can therefore test paths outside `/app/`.

Temporary output is deleted after parsing, but output is read as a whole before row
limits are applied. The current wrapper cannot by itself prove that every selected
template, redirect or secondary request stays within the approved IP/origin policy.
This is a containment/reproducibility gap, not a demonstrated redirect escape.

**Acceptance:** record tested binary/template versions and approved template hashes;
enforce origin/path/egress constraints outside the subprocess; cap output bytes before
parsing. Exercise cross-host redirects, template secondary requests, custom ports,
IPv6, process termination and malformed output with supported real tool versions.
Do not present tag filters as equivalent to deterministic request allowlisting.

### R7: AI paths have different evidence and privacy contracts

**Priority: P1 for opt-in provider use. Confirmed by source.**

`agent.py` and visual analysis request structured schemas and provider controls including
`zdr`, `data_collection=deny`, and `require_parameters`. `system_review.review_run` uses
`json_object` output and does not request those controls. Its parser accepts arbitrary
categories, titles, severity and evidence without checking referenced evidence IDs.
A prompt asking for supported conclusions is not an enforcement boundary. Model output
can repeat sensitive input metadata or unsupported claims into durable findings.

Review IDs use category plus target path, so multiple same-category observations collide
and later additions overwrite earlier ones. MariaDB also omits engine/model attribution
when persisting findings. These issues make model results difficult to audit.

**Acceptance:** use a shared explicit provider/evidence policy, strict response schema,
bounded requests/responses and evidence-ID validation. Record model, prompt hash, policy
and review state in every durable representation. Test malformed responses, invented
evidence, duplicate categories, secret echoing and provider refusal. Request-level
retention flags still require provider-side verification; they are not proof of deletion.

### R8: The passive label hides a broader TLS probe policy

**Priority: P1 policy clarification. Confirmed by source.**

`TlsScanner.scan` runs `_COMMANDS` on default HTTPS scans, including HEARTBLEED, ROBOT,
CCS injection and session renegotiation alongside protocol/certificate checks. These
are active TLS interactions even when the HTTP profile is named passive. This does not
demonstrate a harmful scan, but the default is broader than header/content inspection.

**Acceptance:** document and review the request/handshake characteristics of each TLS
capability; distinguish certificate/protocol inventory from vulnerability probes in the
policy. Put any capability outside the approved default boundary behind an explicit
profile. Test the default command set and opt-in transitions. Do not infer safety solely
from a third-party library's command name or the absence of HTTP write methods.

### R9: History is not a lossless scan archive

**Priority: P2. Confirmed by schema/save-path inspection.**

`storage.MariaDbStore.save` stores selected run/target/finding/component fields, but not
the complete JSON record: script assets, full coverage, run profile and finding
engine/model attribution are missing. `history list` returns summaries only. A local
file cannot be recreated from the database. Runtime migration definitions and SQL files
are duplicated maintenance surfaces. The AWS secret wrapper's allowlist also omits the
new review credentials/options, despite supporting the older AI paths.

**Acceptance:** explicitly define archive versus summary semantics; migrate only fields
required by that contract. Round-trip representative records if archive support is
chosen; test schema-file/runtime parity and secret-wrapper key parity. Document retention,
cleanup and operator ownership of screenshots and derived sensitive metadata.

## What a state-of-the-art tool would add

“State of the art” is evaluated here as useful tested coverage, reproducible evidence,
bounded execution and reliable operations. A feature count or a model-generated summary
does not establish those qualities. Standards below are comparison frameworks, not
claims that an external scanner can verify every application control.

| Area | Present capability | Missing capability / evidence | Priority and acceptance |
| --- | --- | --- | --- |
| Surface discovery | HTML links, GET form actions, robots/sitemap, literal OpenAPI GET seeds | Browser-rendered routes, observed XHR/fetch endpoints, parameter/content-type inventory, path exclusion and scope report | P2: known SPA fixture routes discovered without write actions; exact scope and budget tests |
| Browser security | Static CSP/header checks and optional screenshot review | Deterministic DOM source/sink analysis, browser-observed policy enforcement and client-side data-flow evidence | P2: vulnerable and safe DOM fixtures; evidence tied to concrete runtime behavior |
| API testing | Header/content checks on literal GET paths | OpenAPI parameterized operations/schema validation; richer auth context; GraphQL operation awareness | P2 for read-only inventory, separate profile for mutations; fixture-based endpoint/parameter coverage |
| Vulnerability intelligence | Six bundled advisory ranges, best-effort fingerprints | Maintained ecosystem/version-range feed, provenance, freshness, signed/cached updates, robust bundled-library detection | P2: advisories and detector versions in reports; offline replay, stale-feed behavior and range boundary tests |
| Detection breadth | Headers, cookies, redirects, exposures, TLS, fixed probes | Broad injection classes, validated CORS exploitability, cache behavior, path traversal, request smuggling, SSRF and business logic | P3/separate authorization; class-specific proof and negative fixtures; intrusive/OAST tests never silently enabled |
| Authentication and authorization | No target credentials or sessions | Login/session verification, role separation, object/property authorization comparisons | Separate product decision; synthetic tenants/objects and logout/secret-isolation tests before real use |
| Evidence quality | Signature evidence, fixed confidence, stable rule/path IDs | Per-check execution state, parameter-aware identity, evidence references, CWE/WSTG/ASVS mapping, severity rationale and validation status | P1/P2: no unexecuted check reported clean; fixture-based identity and mapping tests |
| Detection evaluation | Broad deterministic unit suite and browser interception test | Measured precision/recall, intentional-vulnerability and negative corpora, regression tracking, adapter compatibility matrix | P2: publish class-level measured results and known false positives; use owned disposable targets |
| Operations | Per-target deadlines, progress, optional history | Shared origin limits, cooperative cancellation, resumable large jobs, metrics, structured events, predictable provider cost caps | P1 traffic/deadlines, P2 rest; interruption/load/over-budget acceptance tests |
| CI and triage | JSON/SARIF/HTML, compare, severity exit gate | Versioned policy file, reviewed suppressions with expiry, stronger baseline identity, artifact provenance, documented CI examples | P2: policy/suppression expiry tests; reproducible scan manifests and stable schema fixtures |
| Deployment and supply chain | Locked Python dependencies, local verification/build | Tested release artifacts, supported binary/browser matrix, SBOM/provenance, isolated runner packaging | P2: clean-install smoke checks and release artifact verification; pin external engine assets |
| Cloud interpretation | AWS account binding and prompt template | Evidence of actual AWS control-plane settings | Keep explicitly unobserved; any future AWS assessment uses a separate least-privilege collector and authorization |

The prior choice to exclude authenticated testing remains a valid scope constraint.
Its absence limits general DAST coverage but does not make a bounded public-surface
scanner unusable. Business-logic requirements still need application-specific human
judgment even with stronger automation.

## Build or integrate

Retain the existing collector, deterministic checks, normalized evidence and SecMan
integration as the public-surface core. Avoid a generic plugin framework or an
orchestrator rewrite while fixing the concrete result-boundary issues.

For broader DAST, prefer evaluating an opt-in mature engine adapter before implementing
an authenticated browser/session/fuzzing stack here. ZAP's Automation Framework supports
explicit environments, authentication/session handling, browser spiders and sequence
jobs. Burp documents browser-powered crawling and API definition-based auditing. These
are capability benchmarks, not claims that either tool automatically satisfies this
repository's IP-pinning or privacy policy. See the [ZAP framework](https://www.zaproxy.org/docs/automate/automation-framework/),
[Burp crawling](https://portswigger.net/burp/documentation/scanner/crawling), and
[Burp API scanning](https://portswigger.net/burp/documentation/scanner/api-scanning-reqs).

Any such adapter needs its own approved scope, isolated execution/egress, budgets,
credential boundary, versioned profile and lifecycle mapping. It must never inherit
authorization for authenticated or intrusive tests from the existing `--active` flag.
An integration spike should first prove scope containment and normalized result fidelity
on disposable fixtures; only then compare detection coverage and maintenance cost.

## Suggested sequence and exit criteria

1. **Trustworthy results:** address R1–R4 and R7, including cross-adapter fixtures and
   durable deterministic artifacts after provider failure. Exit when optional analysis
   cannot leak query tokens, lose inventory, or falsely resolve unevaluated findings.
2. **Bounded execution:** address R5, R6 and R8. Exit when repeated-origin load,
   cancellation, TLS policy and external-engine egress are measured and enforced.
3. **Best-in-scope coverage:** add a versioned coverage manifest, maintained advisories,
   safe browser/API discovery and an evaluation corpus. Exit when reports identify
   executed/untested checks and measured quality by supported vulnerability class.
4. **Production operations:** define archive/retention semantics, CI policy/suppression,
   supported runtime matrix, integration rehearsals and release provenance. Exit when
   clean-install and disposable end-to-end workflows pass with reproducible artifacts.
5. **Optional broader DAST:** make a separate scope decision and evaluate an isolated
   engine adapter. Authentication, role comparison, mutations, OAST and business-logic
   replay require separate explicit authorization and evidence contracts.

## Review verification and limits

Offline synthetic checks reproduced query retention in review/JSON, loss of a single
script record during `merge_runs`, and a missing `LLM-*` finding reported as resolved
under unchanged passive profiles. The upload/result split, storage omissions,
process-local semaphore and provider-policy differences were traced directly in source.
No real target, secret, model provider, database or SecMan server was used for those checks.

Local verification passed: 299 tests, Ruff lint/format, strict mypy, lockfile validation,
and wheel/source-distribution builds. The initial browser test required installing the
matching Chromium under `/tmp`; the passing rerun used that browser path. CLI reference
coverage was checked against all 31 explicitly declared long options; local document
links and fenced blocks were checked as well.

Tests do not establish production throughput, advisory freshness, external binary
behavior or deployed REST compatibility. Those remain explicit acceptance work above.

## Standards and primary references

Sources checked on 2026-10-20. Capability recommendations are this review's engineering
assessment; referenced sources establish the standards and comparator features.

- [OWASP ASVS](https://owasp.org/projects/asvs): current stable version 5.0.0;
  version requirement identifiers when mapping rules. It covers application controls
  beyond externally observable behavior and cannot be certified by a header scan.
- [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide): release 4.2,
  with 5.0 in development; use released/versioned testing references for reproducibility.
- [OWASP API Security Top 10, 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/):
  object/property authorization and authentication require evidence absent from current
  public GET-path collection.
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/):
  a comparison for scoped plans, authentication, session handling and browser discovery.
- [PortSwigger crawling](https://portswigger.net/burp/documentation/scanner/crawling)
  and [API scanning requirements](https://portswigger.net/burp/documentation/scanner/api-scanning-reqs):
  comparisons for JavaScript-rendered discovery and definition-driven API auditing.

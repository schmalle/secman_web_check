# Architecture remediation implementation

Implemented scope: R1–R9 in [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md), then public-surface
evidence/coverage, shared traffic admission, maintained advisory snapshots, browser-driven
discovery, richer API inventory and measured detection fixtures. The earlier review is
historical. Authentication, mutations, unrestricted fuzzing and business logic are outside
this implementation's authorized scope.

## Findings and verification

| Finding | Implemented behavior | Verification |
| --- | --- | --- |
| R1: location privacy | One public-URL projection strips userinfo/query/fragment at record and serialization boundaries; review sends typed metadata/IDs | Synthetic tokens absent from JSON, SARIF, HTML, terminal and provider projection |
| R2: combined result loss | Merge preserves script/API inventory, evidence records and analysis stages | Non-empty inventories survive security/visual merging |
| R3: review result flow | Per-target failures retain deterministic/earlier evidence; timestamps/stages updated; same observations reach reports/archive/primary upload | Later-target provider failure, archive round trip and snapshot parity fixtures |
| R4: incomplete profiles | Versioned manifest/hash records config, scope, engines/catalogue revisions, API declarations and advisory provenance; comparison checks execution domains | Changed limits, missing manifests, model absence and unsupported/query contexts cannot resolve findings |
| R5: fragmented limits | One process-shared run/origin limiter; HTTP hops, TLS sockets, provider calls and external connections; cancellation/lease reclamation; visual/security hard workers; provider DNS child | Spawned-worker rate/peak-concurrency, global/call caps, cancellation, timeout and socket-hook fixtures |
| R6: external containment | Exact reviewed profile/binary/assets, root authorization, proxy-only macOS sandbox, DNS pinning, native pacing, byte/time/output limits; unsupported platforms fail closed | Asset tampering, scope/method denial and native local-server test; direct egress denied and proxy path succeeds |
| R7: AI contracts | Shared strict/pinned/bounded provider transport and retention request; fixed review categories with known evidence IDs; model/prompt/policy/review attribution | Refusal/malformed/invented evidence rejection, distinct same-category identities, all-adapter provenance |
| R8: TLS policy | Default certificate/protocol inventory; separate `--tls-vulnerabilities`; per-connect DNS and leases | Default command-set/explicit opt-in assertions and DNS-drift refusal |
| R9: full history | Schema 4 archives full normalized JSON transactionally; `history export`; SQL/runtime migration parity; wrapper AI-key parity | Full archive round trip, rollback, legacy-archive errors and migration equivalence |

Baseline SecMan finding/component resolution now additionally needs the exact approved
`SECMAN_BASELINE_PROFILE_SHA256`; absent/mismatched approval keeps uploads non-terminal.
This avoids remote false resolution across changed profiles while the REST API lacks its
own manifest-equivalence contract. Query-bearing, redirected and non-200 contexts stay non-terminal even with approval.
Extended/visual/model snapshots remain non-terminal.

## Added capabilities

- **Evidence and coverage:** typed evidence IDs, rule applicability/outcomes, explicit
  skipped/unsupported/exhausted states, prompt/model/policy/timing, canonical manifest/hash,
  API/script metadata and traffic admissions are available in local and durable output.
- **Maintained intelligence:** explicit OSV package/ID updates discover current advisories;
  normalized atomic snapshots are checksum-pinned and matched offline. Provenance,
  freshness and unsupported ranges are recorded; stale/incomplete feeds mark partial
  coverage. Unknown versions and withdrawn records do not establish vulnerabilities.
- **Browser discovery:** rendered anchors and observed read-only fetch/XHR traverse the
  pinned collector. Scope, page/depth/request/run budgets apply; writes and session replay
  are blocked. Discovery creates no screenshots.
- **API inventory:** OpenAPI methods/placeholders, parameter names/types, content types and
  auth declarations are retained without example/default/parameter values. Only literal
  GET seeds are executed by the existing crawler; observed blocked writes stay inventory-only.
- **Detection measurements:** 20 owned vulnerable/safe fixtures across ten classes, with
  TP/FP/FN/TN and per-class precision/recall, corpus/source revisions and a regression exit
  gate. See [EVALUATION.md](EVALUATION.md) and [results](evaluation/detection-results.json).

## Validation and practical limits

The regular quality gate checks tests, Ruff, strict mypy, lockfile and both package builds.
The native macOS containment fixture is run separately with `SECMAN_TEST_SANDBOX=1` where
nested sandboxing is permitted. It verifies enforcement using curl and local fixture
servers; it does not certify any operator's Nuclei/Nikto binaries/plugins/templates.
External execution currently fails closed on other platforms. Exact installed engine
compatibility and reviewed asset hashes remain explicit installation requirements.

A public OSV jQuery package update was exercised successfully: eight normalized advisory
records were fetched into `/tmp` without transmitting target inventory. An actual SSLyze/Nassl certificate handshake against an owned local TLS fixture also
verified per-socket admission and lease release. Default tests
use fixtures rather than a provider, production database or SecMan deployment. Those
live integrations and production throughput are not inferred from the local gate.

Snapshot SHA-256 verifies the operator-selected artifact and its provenance from a TLS
update; it is not an upstream signature. Default bundled intelligence remains a clearly
labeled legacy subset when no maintained snapshot is selected. The synthetic corpus
measures its stated signature contracts only and is not a general real-world recall claim.
External encrypted tunnel traffic is bounded by admissions, bytes/time and native pacing;
the proxy does not claim to count individual encrypted HTTP requests.

Pre-existing working-tree changes were retained. A before-edit copy under `/tmp` was used
to distinguish implementation changes; no reset/stash or unrelated cleanup was performed.

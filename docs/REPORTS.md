# Report formats

Use repeatable `--format` options or `--format all`. Files are written atomically below
`--output-dir` with the collision-safe run ID in their names.

- `terminal`: human-readable per-target status, exposure, components, incomplete stages, and findings.
- `json`: versioned machine document with `schemaVersion: "1.3"`.
- `sarif`: SARIF `2.1.0` with stable rule IDs, target URLs, and external fingerprints.
- `html`: self-contained, accessible, escaped, script-free report with a restrictive CSP.

The JSON hierarchy is:

```text
runId, profile, startedAt, completedAt
└── targets[]: url, awsAccountNumber, status, complete, inventoryComplete, errors[], timestamps
    ├── coverage: pagesScanned, pagesDiscovered, pages[], crawlRequests,
    │             httpRequests, crawlComplete,
    │             agentActions, agentComplete
    ├── exposure: configuredUrl, effectiveUrl, reachability, httpStatus,
    │             redirectCount, redirectFollowed, bodyLength, vantagePoint
    ├── components[]: componentKey, category, name, version, confidence,
    │                 evidenceType, evidence, sourceUrl
    ├── javascriptAssets[]: url, sha256, sizeBytes, statusCode, truncated
    └── findings[]: ruleId, externalId, severity, confidence, title,
                    description, recommendation, evidence, url, engine, model, createdAt
```

Reports contain normalized findings and sanitized stage errors. They never contain raw
HTTP response bodies, unredacted cookie values, authorization headers, passwords, or
SecMan tokens.
Target and finding URLs omit query and fragment values. Incomplete crawling or agent
coverage marks the target partial, preventing SecMan from resolving absent findings.
`secman-web-check compare OLD NEW --json` reports introduced, resolved, and unconfirmed
absences. It calls an absence resolved only when both reports use the same complete
baseline security profile; optional check profiles and visual observations are
conservative because their coverage can vary between runs.
Component source URLs omit queries and fragments. Component evidence contains a fixed
matched-signature description, never the raw response header or body excerpt.
The `WEB-HEADER-DISCLOSURE` finding identifies PHP, ASP.NET, and Express advertised by
`Server` or `X-Powered-By`, plus ASP.NET/MVC version headers. Its evidence includes
recognized numeric versions without copying arbitrary header contents. This passive
check makes no additional requests. Headers can be hidden or spoofed: a match is an
advertised technology, not proof of execution, and absence does not rule it out.
JavaScript assets are present only when `--javascript-inventory` is selected. The
scanner downloads each referenced external script through its revalidating, pinned HTTP
collector, computes SHA-256 over the received bytes, and immediately discards those
bytes. Reports contain metadata and checksums only. A truncated asset is explicitly
marked and its checksum covers only the collected prefix.

Findings returned by `--llm-review` identify the
`secman-web-check-openrouter` engine and selected model. The review receives the same
sanitized evidence represented by the report and never receives response bodies.

`awsAccountNumber` is a nullable string. It is populated when the target came from
`--targets-csv` and omitted as `null` for positional, plain-file, and SecMan-bound targets.

Exposure `reachability` is `REACHABLE`, `AUTHENTICATED`, or `UNKNOWN`. `AUTHENTICATED`
means the collected body was exactly `{"message":"Missing Authentication Token"}`
(ignoring surrounding whitespace), the AWS API Gateway response for an endpoint that
requires authentication. `bodyLength` is the number of response body bytes received
under the configured body limit; it is `null` when collection failed.
Exposure `redirectFollowed` is `true` when the collector followed at least one HTTP
redirect for the target URL, `false` when it collected a response without following
one, and `null` when no HTTP response was available. HTML and terminal reports show
Yes, No, or Unknown. The findings CSV repeats the flag in `redirect_followed`.
Target `browserNavigationObserved` reports whether the final browser URL differed from
the initial document response URL during the observation window in browser discovery
or visual mode. A skipped or failed observation is Unknown (`null`), including when
page scripts fail and no navigation is observed. The findings CSV uses
`browser_navigation_observed`.
The optional `browserNavigationDiagnostic` gives the reason for incomplete observation.
`script-failure` identifies a page script that failed to load or run.
`blocked-origin` records a main-frame navigation attempt outside the browser origin
allowlist. It includes only the destination hostname. The CSV columns are
`browser_navigation_reason` and `browser_navigation_hostname`.
`blocked-http-redirect` identifies a server redirect returned to the isolated browser's
request and stopped before connecting to its destination. Browser requests use a
Chromium User-Agent without the headless marker to observe ordinary browser responses.
For an eligible no-redirect response, the default security scan makes one additional
pinned GET using a Chromium User-Agent. `browserHttp` records the status and any
redirect destination hostname from that request. The scanner does not follow that
destination as part of this probe. A null observation means it was not checked, and
a null status means the check was inconclusive.
With `--browser-redirects`, Playwright observes the starting page for up to five seconds
after document load within the browser deadline. `browserNavigationHops` lists the
observed destination hostnames, including a destination blocked by policy. An explicit
`--allowed-origin` can permit the next document hop. Each server redirect is passed back
to the pinned collector before following it, including same-origin hops.


## Evidence and provenance (schema 1.3)

The run includes `coverageManifest`, its canonical `profileHash` and `trafficMetrics`.
Targets include `evidenceRecords`, `analysisStages`, `apiOperations`, script metadata and
`coverage.executions`. Execution states are executed-positive, executed-negative, skipped,
unsupported, failed or exhausted. Finding evidence IDs resolve to typed deterministic
signature records or reviewed crop checksums; bodies and images are not embedded.

Findings record `validationStatus`, `evidenceIds`, model, prompt hash and provider-policy
version. Model observations require human review and do not prove resolution when absent.
SARIF properties preserve attribution/coverage metadata; HTML/terminal expose check states,
API metadata and attribution. MariaDB archives the same full JSON document transactionally.
SecMan metadata carries the same provenance while preserving its REST v1 request schema.

Comparison now requires a validated matching manifest/hash and an executed check domain.
Legacy reports, query-bearing contexts, skipped/unsupported checks and variable analysis
cannot confirm resolution. See CLI.md for the full contract.

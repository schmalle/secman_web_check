# Report formats

Use repeatable `--format` options or `--format all`. Files are written atomically below
`--output-dir` with the collision-safe run ID in their names.

- `terminal`: human-readable per-target status, exposure, components, incomplete stages, and findings.
- `json`: versioned machine document with `schemaVersion: "1.2"`.
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
    │             redirectCount, bodyLength, vantagePoint
    ├── components[]: componentKey, category, name, version, confidence,
    │                 evidenceType, evidence, sourceUrl
    └── findings[]: ruleId, externalId, severity, confidence, title,
                    description, recommendation, evidence, url, createdAt
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

`awsAccountNumber` is a nullable string. It is populated when the target came from
`--targets-csv` and omitted as `null` for positional, plain-file, and SecMan-bound targets.

Exposure `reachability` is `REACHABLE`, `AUTHENTICATED`, or `UNKNOWN`. `AUTHENTICATED`
means the collected body was exactly `{"message":"Missing Authentication Token"}`
(ignoring surrounding whitespace), the AWS API Gateway response for an endpoint that
requires authentication. `bodyLength` is the number of response body bytes received
under the configured body limit; it is `null` when collection failed.

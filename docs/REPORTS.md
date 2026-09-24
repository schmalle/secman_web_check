# Report formats

Use repeatable `--format` options or `--format all`. Files are written atomically below
`--output-dir` with the collision-safe run ID in their names.

- `terminal`: human-readable per-target status, exposure, components, incomplete stages, and findings.
- `json`: versioned machine document with `schemaVersion: "1.2"`.
- `sarif`: SARIF `2.1.0` with stable rule IDs, target URLs, and external fingerprints.
- `html`: self-contained, accessible, escaped, script-free report with a restrictive CSP.

The JSON hierarchy is:

```text
runId, startedAt, completedAt
└── targets[]: url, awsAccountNumber, status, complete, inventoryComplete, errors[], timestamps
    ├── exposure: configuredUrl, effectiveUrl, reachability, httpStatus,
    │             redirectCount, bodyLength, vantagePoint
    ├── components[]: componentKey, category, name, version, confidence,
    │                 evidenceType, evidence, sourceUrl
    ├── javascriptAssets[]: url, sha256, sizeBytes, statusCode, truncated
    └── findings[]: ruleId, externalId, severity, confidence, title,
                    description, recommendation, evidence, url, engine, model, createdAt
```

Reports contain normalized findings and sanitized stage errors. They never contain raw
HTTP response bodies, unredacted cookie values, authorization headers, passwords, or
SecMan tokens.
Component source URLs omit queries and fragments. Component evidence contains a fixed
matched-signature description, never the raw response header or body excerpt.
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

# Report formats

Use repeatable `--format` options or `--format all`. Files are written atomically below
`--output-dir` with the collision-safe run ID in their names.

- `terminal`: human-readable per-target status, incomplete stages, and finding table.
- `json`: versioned machine document with `schemaVersion: "1.0"`.
- `sarif`: SARIF `2.1.0` with stable rule IDs, target URLs, and external fingerprints.
- `html`: self-contained, accessible, escaped, script-free report with a restrictive CSP.

The JSON hierarchy is:

```text
runId, startedAt, completedAt
└── targets[]: url, awsAccountNumber, status, complete, errors[], timestamps
    └── findings[]: ruleId, externalId, severity, confidence, title,
                    description, recommendation, evidence, url, createdAt
```

Reports contain normalized findings and sanitized stage errors. They never contain raw
HTTP response bodies, unredacted cookie values, authorization headers, passwords, or
SecMan tokens.

`awsAccountNumber` is a nullable string. It is populated when the target came from
`--targets-csv` and omitted as `null` for positional and plain-file targets.

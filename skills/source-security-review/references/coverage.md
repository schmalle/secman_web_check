# Select checks from the observed architecture

Use OWASP web and API risk categories as a baseline. For each applicable area, inspect the actual decision point and its callers. A checklist match opens an investigation. A finding requires the evidence described in SKILL.md.

| Area | Questions for source inspection |
|---|---|
| Identity and sessions | Where are issuer, audience, signature, expiry and session lifecycle enforced? Which routes bypass middleware? Who can trigger recovery or account linking? |
| Authorization and isolation | Do list, detail, bulk, export and background paths bind the authenticated principal to the requested tenant, object, operation and fields? Does storage enforce the same restriction? |
| Input and interpretation | Does external input reach SQL, commands, templates, filenames, outbound destinations, parsers or deserializers? Does the control apply to the final interpreted value? |
| Browser and API | Inspect output encoding, DOM insertion, credentialed cross-origin access, CSRF protection, redirects, caches, upload serving, response serialization and writable fields. |
| Business logic and concurrency | Who controls transitions, amounts and approvals? Inspect duplicate delivery, transaction boundaries, idempotency, replay and competing updates. |
| Secrets, crypto and data | Trace keys and sensitive data through storage, transport, logs, telemetry, artifacts and deletion. Check verification, key use and access to outputs. Redact values. |
| Availability and errors | Look for unbounded shared work, queues, request sizes, pagination and retry loops. Check failure behavior at authorization and transaction boundaries. Identify who else is affected. |
| Logging and monitoring | For sensitive operations inspect actor attribution, tenant attribution, redaction and handling of untrusted log fields. Identify the concrete consequence of missing or misleading records. |
| Dependencies and release | Inspect lockfiles, package sources, build inputs, artifact integrity and release provenance. Distinguish production, build-time and development exposure. |
| CI/CD | Trace workflow triggers, untrusted contributions, token permissions, secret availability, caches, artifacts and runner isolation through release jobs. |
| Containers and infrastructure | Inspect effective users, mounts, capabilities, workload identity, ingress and egress, public exposure, IAM conditions, resource policies, encryption and environment overrides. |
| Backend workers and integrations | Trace queue publishers, webhook authentication, tenant context, serialization and authorization at consumption. Check whether retries repeat privileged actions. |
| Stack-specific features | Add relevant checks for native memory ownership, local IPC, plugin execution or model tool authorization when those boundaries appear in the target. |

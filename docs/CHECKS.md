# Checks and severities

All rules emit a stable `WEB-*` ID, bounded signature-only evidence, severity,
confidence, rationale, and remediation. Titles, descriptions, and remediation text live
in the immutable catalogue in `src/checks/registry.py`.

## Passive HTTP and content rules

| Rule ID | Severity |
| --- | --- |
| `WEB-HEADER-HSTS-MISSING` | MEDIUM |
| `WEB-HEADER-HSTS-WEAK` | LOW |
| `WEB-HEADER-CSP-MISSING` | MEDIUM |
| `WEB-HEADER-CSP-UNSAFE` | MEDIUM |
| `WEB-HEADER-NOSNIFF-MISSING` | LOW |
| `WEB-HEADER-FRAMING-MISSING` | MEDIUM |
| `WEB-HEADER-REFERRER-POLICY-MISSING` | LOW |
| `WEB-HEADER-REFERRER-POLICY-WEAK` | LOW |
| `WEB-HEADER-PERMISSIONS-POLICY-MISSING` | INFO |
| `WEB-HEADER-COOP-MISSING` | INFO |
| `WEB-HEADER-COEP-MISSING` | INFO |
| `WEB-HEADER-CORP-MISSING` | INFO |
| `WEB-HEADER-CACHE-SENSITIVE` | LOW |
| `WEB-HEADER-DISCLOSURE` | LOW |
| `WEB-COOKIE-SECURE-MISSING` | MEDIUM |
| `WEB-COOKIE-HTTPONLY-MISSING` | LOW |
| `WEB-COOKIE-SAMESITE-MISSING` | LOW |
| `WEB-COOKIE-SAMESITE-NONE-INSECURE` | LOW |
| `WEB-COOKIE-PREFIX-INVALID` | LOW |
| `WEB-COOKIE-DOMAIN-BROAD` | LOW |
| `WEB-CORS-WILDCARD` | INFO |
| `WEB-CORS-WILDCARD-CREDENTIALS` | LOW |
| `WEB-TRANSPORT-HTTPS-DOWNGRADE` | MEDIUM |
| `WEB-TRANSPORT-REDIRECT` | INFO |
| `WEB-TRANSPORT-CROSS-HOST-REDIRECT` | LOW |
| `WEB-TRANSPORT-REDIRECT-BLOCKED` | LOW |
| `WEB-CONTENT-DIRECTORY-LISTING` | MEDIUM |
| `WEB-CONTENT-DEBUG-ERROR` | MEDIUM |
| `WEB-CONTENT-INTERNAL-ADDRESS` | LOW |
| `WEB-CONTENT-INSECURE-FORM` | MEDIUM |
| `WEB-CONTENT-MIXED-ACTIVE` | MEDIUM |
| `WEB-CONTENT-SECRET` | HIGH |
| `WEB-CONTENT-SECURITY-TXT-MISSING` | INFO |
| `WEB-CONTENT-SECURITY-TXT-INVALID` | INFO |
| `WEB-CONTENT-SECURITY-TXT-EXPIRED` | INFO |

## Active rules

These rules run only with `--active`. See [SAFETY.md](SAFETY.md) for the exact requests
and signature requirements.

| Rule ID | Severity |
| --- | --- |
| `WEB-ACTIVE-TRACE-REFLECTION` | MEDIUM |
| `WEB-ACTIVE-UNSAFE-METHODS` | LOW |
| `WEB-ACTIVE-ENV-EXPOSED` | HIGH |
| `WEB-ACTIVE-GIT-EXPOSED` | HIGH |
| `WEB-ACTIVE-SERVER-STATUS-EXPOSED` | MEDIUM |
| `WEB-ACTIVE-CONFIG-BACKUP-EXPOSED` | HIGH |

## TLS rules

| Rule ID | Severity |
| --- | --- |
| `WEB-TLS-PROTOCOL-SSL-2` | CRITICAL |
| `WEB-TLS-PROTOCOL-SSL-3` | HIGH |
| `WEB-TLS-PROTOCOL-1-0` | HIGH |
| `WEB-TLS-PROTOCOL-1-1` | MEDIUM |
| `WEB-TLS-CERTIFICATE-UNTRUSTED` | HIGH |
| `WEB-TLS-CERTIFICATE-EXPIRED` | HIGH |
| `WEB-TLS-CERTIFICATE-EXPIRING` | MEDIUM |
| `WEB-TLS-CERTIFICATE-WEAK-KEY` | HIGH |
| `WEB-TLS-CERTIFICATE-SHA1` | HIGH |
| `WEB-TLS-COMPRESSION` | MEDIUM |
| `WEB-TLS-WEAK-CIPHER` | HIGH |
| `WEB-TLS-FALLBACK-SCSV-MISSING` | LOW |
| `WEB-TLS-INSECURE-RENEGOTIATION` | HIGH |
| `WEB-TLS-CLIENT-RENEGOTIATION-DOS` | HIGH |
| `WEB-TLS-HEARTBLEED` | CRITICAL |
| `WEB-TLS-CCS-INJECTION` | CRITICAL |
| `WEB-TLS-ROBOT` | CRITICAL |

INFO/LOW items are hardening or review signals. MEDIUM identifies meaningful security
weaknesses. HIGH identifies likely serious exposure or deprecated controls. CRITICAL is
reserved for obsolete protocol support or a known TLS vulnerability probe reporting a
vulnerable endpoint. Lower-confidence heuristic findings are explicitly marked in the
machine reports and require contextual validation.

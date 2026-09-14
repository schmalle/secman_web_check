"""Fixed passive rule metadata and the collected-evidence check contract."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType

from ..http import HttpResponseEvidence
from ..models import Finding, Severity


@dataclass(frozen=True, slots=True)
class CheckContext:
    response: HttpResponseEvidence
    security_txt: HttpResponseEvidence | None = None
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    def header_values(self, name: str) -> tuple[str, ...]:
        return tuple(value for key, value in self.response.headers if key.lower() == name.lower())

    @property
    def is_html(self) -> bool:
        values = self.header_values("content-type")
        return bool(
            values
            and values[0].split(";", 1)[0].strip().lower() in {"text/html", "application/xhtml+xml"}
        )


Check = Callable[[CheckContext], tuple[Finding, ...]]


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    confidence: float = 1.0

    def finding(self, context: CheckContext, evidence: str) -> Finding:
        # Callers pass only fixed signatures, directive names and numeric cookie positions.
        # No response values or body excerpts should ever cross this persistence boundary.
        return Finding.create(
            self.rule_id,
            context.response.url,
            self.severity,
            self.title,
            confidence=self.confidence,
            description=self.description,
            recommendation=self.recommendation,
            evidence=evidence.replace("\r", " ").replace("\n", " ")[:512],
        )


_CATALOGUE = (
    Rule(
        "WEB-HEADER-HSTS-MISSING",
        Severity.MEDIUM,
        "HSTS header is missing",
        "HTTPS responses without HSTS do not instruct browsers to require HTTPS on later visits.",
        "Serve Strict-Transport-Security over HTTPS with max-age of at least 15552000 seconds.",
    ),
    Rule(
        "WEB-HEADER-HSTS-WEAK",
        Severity.LOW,
        "HSTS policy is weak or invalid",
        "The first HSTS header does not establish at least 180 days of HTTPS enforcement.",
        "Use a valid single max-age directive of at least 15552000 seconds.",
    ),
    Rule(
        "WEB-HEADER-CSP-MISSING",
        Severity.MEDIUM,
        "Enforced CSP is missing",
        "This HTML response has no enforced Content-Security-Policy to limit injected content.",
        "Deploy an enforced CSP with narrow sources, nonces or hashes for scripts, and no eval.",
    ),
    Rule(
        "WEB-HEADER-CSP-UNSAFE",
        Severity.MEDIUM,
        "CSP permits broad or unsafe script sources",
        "Every observed CSP permits at least one shared unsafe script capability. This is a "
        "policy weakness, not proof of script injection.",
        "Restrict script sources and remove wildcards, insecure schemes, unsafe-inline and unsafe-eval.",
        0.9,
    ),
    Rule(
        "WEB-HEADER-NOSNIFF-MISSING",
        Severity.LOW,
        "MIME sniffing protection is missing",
        "X-Content-Type-Options does not contain a valid nosniff policy.",
        "Send X-Content-Type-Options: nosniff and accurate content types.",
    ),
    Rule(
        "WEB-HEADER-FRAMING-MISSING",
        Severity.MEDIUM,
        "Framing protection is missing",
        "This HTML response has neither a restrictive frame-ancestors policy nor valid X-Frame-Options.",
        "Set CSP frame-ancestors to an explicit allowlist or 'none'; use DENY or SAMEORIGIN for XFO.",
    ),
    Rule(
        "WEB-HEADER-REFERRER-POLICY-MISSING",
        Severity.LOW,
        "Referrer policy is missing or invalid",
        "The HTML response does not explicitly set a recognized Referrer-Policy.",
        "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
    ),
    Rule(
        "WEB-HEADER-REFERRER-POLICY-WEAK",
        Severity.LOW,
        "Referrer policy permits excess disclosure",
        "The effective referrer policy can expose URL information across origins or downgrades.",
        "Use no-referrer, same-origin, strict-origin or strict-origin-when-cross-origin.",
    ),
    Rule(
        "WEB-HEADER-PERMISSIONS-POLICY-MISSING",
        Severity.INFO,
        "Permissions policy is missing",
        "The document does not explicitly restrict browser feature permissions.",
        "Disable unused browser features with a Permissions-Policy appropriate to the application.",
    ),
    Rule(
        "WEB-HEADER-COOP-MISSING",
        Severity.INFO,
        "Cross-origin opener isolation is absent",
        "The HTML response does not opt into an isolating COOP policy; applicability depends on usage.",
        "Consider Cross-Origin-Opener-Policy: same-origin after testing popup and sign-in flows.",
    ),
    Rule(
        "WEB-HEADER-COEP-MISSING",
        Severity.INFO,
        "Cross-origin embedder isolation is absent",
        "The HTML response does not opt into COEP isolation; this is optional application hardening.",
        "Consider require-corp or credentialless where cross-origin isolation is required.",
    ),
    Rule(
        "WEB-HEADER-CORP-MISSING",
        Severity.INFO,
        "Cross-origin resource restriction is absent",
        "The HTML response does not restrict cross-origin resource use with CORP.",
        "Consider same-origin or same-site after reviewing legitimate cross-origin consumers.",
    ),
    Rule(
        "WEB-HEADER-CACHE-SENSITIVE",
        Severity.LOW,
        "Cookie-setting response lacks no-store",
        "A response setting cookies lacks an explicit no-store directive; review whether its body "
        "contains sensitive data before treating caching as exposure.",
        "Send Cache-Control: no-store for responses containing session or personal data.",
        0.7,
    ),
    Rule(
        "WEB-HEADER-DISCLOSURE",
        Severity.LOW,
        "Technology disclosure header is present",
        "Response headers advertise a technology or server version useful for fingerprinting.",
        "Remove unnecessary technology headers and suppress detailed server version banners.",
        0.9,
    ),
    Rule(
        "WEB-COOKIE-SECURE-MISSING",
        Severity.MEDIUM,
        "Cookie lacks Secure",
        "A cookie without Secure can be sent over unencrypted HTTP.",
        "Set Secure on cookies and serve the application over HTTPS.",
    ),
    Rule(
        "WEB-COOKIE-HTTPONLY-MISSING",
        Severity.LOW,
        "Cookie lacks HttpOnly",
        "The cookie is available to page scripts. Some non-session cookies legitimately need this.",
        "Set HttpOnly on session and sensitive cookies that JavaScript does not need.",
    ),
    Rule(
        "WEB-COOKIE-SAMESITE-MISSING",
        Severity.LOW,
        "Cookie SameSite policy is missing or invalid",
        "The cookie relies on browser default cross-site behavior instead of an explicit valid policy.",
        "Set SameSite=Lax or Strict where compatible; review explicit None for cross-site needs.",
    ),
    Rule(
        "WEB-COOKIE-SAMESITE-NONE-INSECURE",
        Severity.LOW,
        "SameSite=None cookie lacks Secure",
        "Modern browsers reject SameSite=None cookies without Secure.",
        "Add Secure to cookies using SameSite=None.",
    ),
    Rule(
        "WEB-COOKIE-PREFIX-INVALID",
        Severity.LOW,
        "Cookie prefix requirements are violated",
        "A __Host- or __Secure- cookie violates its secure origin, Secure, Domain or Path contract.",
        "Set prefixed cookies over HTTPS with Secure; __Host- also requires Path=/ and no Domain.",
    ),
    Rule(
        "WEB-COOKIE-DOMAIN-BROAD",
        Severity.LOW,
        "Cookie is scoped to a parent domain",
        "A parent-domain cookie is shared across subdomains and expands the cookie trust boundary.",
        "Omit Domain for host-only cookies unless sharing with sibling subdomains is required.",
        0.9,
    ),
    Rule(
        "WEB-CORS-WILDCARD",
        Severity.INFO,
        "CORS wildcard origin is configured",
        "The response advertises public cross-origin reading. Public resources may intentionally "
        "use this; duplicate headers or other browser checks may prevent access.",
        "Use an explicit origin allowlist for data that is not intended for public cross-origin use.",
    ),
    Rule(
        "WEB-CORS-WILDCARD-CREDENTIALS",
        Severity.LOW,
        "CORS wildcard and credentials conflict",
        "The response combines wildcard origin with credentials. Browsers reject credentialed "
        "reads under this policy; this does not prove credentialed data exfiltration.",
        "Use explicit allowed origins with credentials, or disable credential support.",
    ),
    Rule(
        "WEB-TRANSPORT-HTTPS-DOWNGRADE",
        Severity.MEDIUM,
        "HTTPS redirects to HTTP",
        "An HTTPS redirect points to unencrypted HTTP, even if collection blocked the redirect.",
        "Keep every redirect destination on HTTPS.",
    ),
    Rule(
        "WEB-TRANSPORT-REDIRECT",
        Severity.INFO,
        "HTTP redirect observed",
        "The explicit target returned a redirect that passed target-policy revalidation.",
        "Confirm that the destination and redirect chain are intentional.",
    ),
    Rule(
        "WEB-TRANSPORT-CROSS-HOST-REDIRECT",
        Severity.LOW,
        "Redirect crosses a host boundary",
        "The explicit target redirected to a different hostname after policy revalidation.",
        "Confirm that the external hostname is trusted and required for this workflow.",
        0.9,
    ),
    Rule(
        "WEB-TRANSPORT-REDIRECT-BLOCKED",
        Severity.LOW,
        "Redirect was not followed",
        "The collector stopped a redirect because it was unsafe, invalid, or exceeded policy.",
        "Correct the redirect destination or chain so it remains valid and within policy.",
    ),
    Rule(
        "WEB-CONTENT-DIRECTORY-LISTING",
        Severity.MEDIUM,
        "Directory listing indicators found",
        "The HTML contains both an index heading and a parent-directory navigation indicator.",
        "Disable directory auto-indexing and publish only intended resources.",
        0.9,
    ),
    Rule(
        "WEB-CONTENT-DEBUG-ERROR",
        Severity.MEDIUM,
        "Detailed runtime error indicators found",
        "Multiple stack trace or debug-page indicators suggest implementation details are exposed.",
        "Disable production debug pages and return generic errors; retain details in protected logs.",
        0.9,
    ),
    Rule(
        "WEB-CONTENT-INTERNAL-ADDRESS",
        Severity.LOW,
        "Internal address reference found",
        "A private or local IP literal appears in a URL or an explicit server/address field.",
        "Remove unintended internal network references from publicly served responses.",
        0.8,
    ),
    Rule(
        "WEB-CONTENT-INSECURE-FORM",
        Severity.MEDIUM,
        "Form uses insecure transport",
        "A form submits to HTTP from HTTPS, or a password form is served or submitted over HTTP.",
        "Serve credential forms over HTTPS and use HTTPS submission URLs.",
        0.95,
    ),
    Rule(
        "WEB-CONTENT-MIXED-ACTIVE",
        Severity.MEDIUM,
        "HTTP active resource appears in HTTPS HTML",
        "An HTTPS document references scripts, styles, frames or embedded active content over HTTP. "
        "Browser blocking or a CSP upgrade policy may mitigate execution.",
        "Use HTTPS URLs for all active document resources.",
        0.95,
    ),
    Rule(
        "WEB-CONTENT-SECRET",
        Severity.HIGH,
        "Private key material indicators found",
        "Matching PEM private key delimiters enclose content in the response; verify authenticity.",
        "Remove exposed key material, investigate access and rotate the key if authentic.",
        0.9,
    ),
    Rule(
        "WEB-CONTENT-SECURITY-TXT-MISSING",
        Severity.INFO,
        "security.txt is absent",
        "The collected security.txt response returned 404 or 410.",
        "Publish /.well-known/security.txt with Contact and Expires fields.",
    ),
    Rule(
        "WEB-CONTENT-SECURITY-TXT-INVALID",
        Severity.INFO,
        "security.txt fields are invalid",
        "The collected security.txt lacks valid Contact or timezone-qualified Expires fields, "
        "or was not served as text/plain.",
        "Publish text/plain security.txt with a contact URI and an RFC 3339 Expires timestamp.",
    ),
    Rule(
        "WEB-CONTENT-SECURITY-TXT-EXPIRED",
        Severity.INFO,
        "security.txt has expired",
        "The collected security.txt expiry is in the past.",
        "Review the security contact information and update the Expires timestamp.",
    ),
    Rule(
        "WEB-ACTIVE-TRACE-REFLECTION",
        Severity.MEDIUM,
        "TRACE reflects request data",
        "The server reflected a synthetic request header in a TRACE response.",
        "Disable TRACE unless it is explicitly required and protected.",
        0.95,
    ),
    Rule(
        "WEB-ACTIVE-UNSAFE-METHODS",
        Severity.LOW,
        "Potentially unsafe HTTP methods are advertised",
        "An OPTIONS response advertises methods that can modify server-side resources.",
        "Restrict allowed methods to those required by the application and enforce authorization.",
        0.7,
    ),
    Rule(
        "WEB-ACTIVE-ENV-EXPOSED",
        Severity.HIGH,
        "Environment configuration appears exposed",
        "A fixed .env probe returned multiple environment-variable signatures.",
        "Block access to dotfiles and rotate any exposed credentials.",
        0.95,
    ),
    Rule(
        "WEB-ACTIVE-GIT-EXPOSED",
        Severity.HIGH,
        "Git metadata appears exposed",
        "A fixed .git/HEAD probe returned a Git reference signature.",
        "Block access to repository metadata and review the deployed document root.",
        0.98,
    ),
    Rule(
        "WEB-ACTIVE-SERVER-STATUS-EXPOSED",
        Severity.MEDIUM,
        "Server status page appears exposed",
        "A fixed server-status probe returned server-status signatures.",
        "Restrict operational status endpoints to authorized administrators.",
        0.9,
    ),
    Rule(
        "WEB-ACTIVE-CONFIG-BACKUP-EXPOSED",
        Severity.HIGH,
        "Configuration backup appears exposed",
        "A fixed backup-file probe returned application configuration signatures.",
        "Remove backup files from the web root and rotate any exposed credentials.",
        0.95,
    ),
    Rule(
        "WEB-TLS-PROTOCOL-SSL-2",
        Severity.CRITICAL,
        "SSL 2.0 is supported",
        "The endpoint accepted an SSL 2.0 cipher suite.",
        "Disable SSL 2.0 and permit only modern TLS protocols.",
    ),
    Rule(
        "WEB-TLS-PROTOCOL-SSL-3",
        Severity.HIGH,
        "SSL 3.0 is supported",
        "The endpoint accepted an SSL 3.0 cipher suite.",
        "Disable SSL 3.0 and permit only modern TLS protocols.",
    ),
    Rule(
        "WEB-TLS-PROTOCOL-1-0",
        Severity.HIGH,
        "TLS 1.0 is supported",
        "The endpoint accepted a TLS 1.0 cipher suite.",
        "Disable TLS 1.0 and require TLS 1.2 or newer.",
    ),
    Rule(
        "WEB-TLS-PROTOCOL-1-1",
        Severity.MEDIUM,
        "TLS 1.1 is supported",
        "The endpoint accepted a TLS 1.1 cipher suite.",
        "Disable TLS 1.1 and require TLS 1.2 or newer.",
    ),
    Rule(
        "WEB-TLS-CERTIFICATE-UNTRUSTED",
        Severity.HIGH,
        "Certificate validation failed",
        "No configured trust store validated the certificate chain and server name.",
        "Install a trusted certificate whose names include the target hostname.",
    ),
    Rule(
        "WEB-TLS-CERTIFICATE-EXPIRED",
        Severity.HIGH,
        "Certificate is expired",
        "The leaf certificate validity period has ended.",
        "Replace the certificate and automate renewal monitoring.",
    ),
    Rule(
        "WEB-TLS-CERTIFICATE-EXPIRING",
        Severity.MEDIUM,
        "Certificate expires soon",
        "The leaf certificate expires within 30 days.",
        "Renew the certificate before expiration.",
    ),
    Rule(
        "WEB-TLS-CERTIFICATE-WEAK-KEY",
        Severity.HIGH,
        "Certificate public key is weak",
        "The leaf certificate uses an undersized RSA or elliptic-curve public key.",
        "Replace the certificate with a modern key size.",
    ),
    Rule(
        "WEB-TLS-CERTIFICATE-SHA1",
        Severity.HIGH,
        "Certificate chain uses SHA-1",
        "The verified certificate chain contains a SHA-1 signature.",
        "Replace the affected certificate chain with SHA-256 or stronger signatures.",
    ),
    Rule(
        "WEB-TLS-COMPRESSION",
        Severity.MEDIUM,
        "TLS compression is enabled",
        "The endpoint supports TLS-level compression.",
        "Disable TLS compression.",
    ),
    Rule(
        "WEB-TLS-WEAK-CIPHER",
        Severity.HIGH,
        "Weak TLS cipher suite is supported",
        "The endpoint accepted a cipher suite using RC4, DES, 3DES, NULL or export cryptography.",
        "Disable weak cipher suites and prefer authenticated AEAD suites.",
    ),
    Rule(
        "WEB-TLS-FALLBACK-SCSV-MISSING",
        Severity.LOW,
        "TLS fallback protection is missing",
        "The endpoint does not support TLS_FALLBACK_SCSV.",
        "Enable TLS fallback signaling or remove legacy protocol support.",
    ),
    Rule(
        "WEB-TLS-INSECURE-RENEGOTIATION",
        Severity.HIGH,
        "Secure TLS renegotiation is unsupported",
        "The endpoint does not support secure renegotiation.",
        "Enable secure renegotiation or disable renegotiation.",
    ),
    Rule(
        "WEB-TLS-CLIENT-RENEGOTIATION-DOS",
        Severity.HIGH,
        "Client-initiated renegotiation is unbounded",
        "The endpoint appears vulnerable to client-initiated renegotiation denial of service.",
        "Disable client-initiated renegotiation or enforce strict limits.",
    ),
    Rule(
        "WEB-TLS-HEARTBLEED",
        Severity.CRITICAL,
        "Endpoint is vulnerable to Heartbleed",
        "The bounded SSLyze Heartbleed probe reported the endpoint as vulnerable.",
        "Patch the TLS library, replace affected keys and certificates, and rotate secrets.",
    ),
    Rule(
        "WEB-TLS-CCS-INJECTION",
        Severity.CRITICAL,
        "Endpoint is vulnerable to CCS injection",
        "The bounded SSLyze CCS injection probe reported the endpoint as vulnerable.",
        "Patch the TLS implementation and remove vulnerable versions.",
    ),
    Rule(
        "WEB-TLS-ROBOT",
        Severity.CRITICAL,
        "Endpoint is vulnerable to ROBOT",
        "The bounded SSLyze ROBOT probe detected an RSA padding oracle.",
        "Disable vulnerable RSA key exchange and patch the TLS implementation.",
    ),
)

RULES = MappingProxyType({rule.rule_id: rule for rule in _CATALOGUE})

"""Pinned SSLyze adapter that immediately translates results to scanner models."""

from __future__ import annotations

import math
import threading
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sslyze import (  # type: ignore[attr-defined]
    ScanCommand,
    Scanner,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
)
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum

from .checks.registry import RULES
from .config import ScannerConfig
from .models import Finding
from .targets import AddressPolicy, NormalizedTarget, resolve_allowed


@dataclass(frozen=True, slots=True)
class TlsEvidence:
    complete: bool
    errors: tuple[str, ...] = ()


_COMMANDS = {
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.TLS_FALLBACK_SCSV,
    ScanCommand.HEARTBLEED,
    ScanCommand.ROBOT,
    ScanCommand.SESSION_RENEGOTIATION,
}

# Bound process-wide TLS scan parallelism: each SSLyze scan opens many sockets,
# and unbounded bursts make servers drop or throttle connections mid-scan.
_SCAN_GATE = threading.Semaphore(3)


def _finding(rule_id: str, target: NormalizedTarget, evidence: str) -> Finding:
    rule = RULES[rule_id]
    return Finding.create(
        rule.rule_id,
        target.url,
        rule.severity,
        rule.title,
        confidence=rule.confidence,
        description=rule.description,
        recommendation=rule.recommendation,
        evidence=evidence,
    )


def _trace_summary(trace: Any) -> str | None:
    if trace is None:
        return None
    summary = "".join(trace.format_exception_only()).strip()
    return summary or None


def _connectivity_error(result: Any) -> str:
    detail = _trace_summary(result.connectivity_error_trace)
    if detail is None:
        return "TLS connectivity failed"
    return f"TLS connectivity failed: {detail}"


class TlsScanner:
    """Run a bounded SSLyze scan against an already policy-approved IP."""

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config if config is not None else ScannerConfig()

    def scan(self, target: NormalizedTarget) -> tuple[TlsEvidence, tuple[Finding, ...]]:
        if target.scheme != "https":
            return TlsEvidence(True), ()
        addresses = resolve_allowed(target, AddressPolicy.from_config(self.config))
        location = ServerNetworkLocation(
            hostname=target.host,
            port=target.port or 443,
            ip_address=addresses[0],
        )
        network = ServerNetworkConfiguration(
            tls_server_name_indication=target.host,
            http_user_agent="secman-web-check/0.1",
            network_timeout=max(1, math.ceil(self.config.connect_timeout_seconds)),
            network_max_retries=3,
        )
        with _SCAN_GATE, warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="Parsed a serial number which wasn't positive.*",
                category=Warning,
            )
            scanner = Scanner(
                per_server_concurrent_connections_limit=2, concurrent_server_scans_limit=1
            )
            scanner.queue_scans(
                [
                    ServerScanRequest(
                        location, network_configuration=network, scan_commands=_COMMANDS
                    )
                ]
            )
            result = next(scanner.get_results())
        if result.scan_result is None:
            return TlsEvidence(False, (_connectivity_error(result),)), ()
        return self._translate(target, result.scan_result)

    def _translate(
        self, target: NormalizedTarget, attempts: Any
    ) -> tuple[TlsEvidence, tuple[Finding, ...]]:
        errors: list[str] = []
        findings: list[Finding] = []
        results: dict[str, Any | None] = {}

        def completed(name: str) -> Any | None:
            if name in results:
                return results[name]
            attempt = getattr(attempts, name)
            if (
                attempt.status is not ScanCommandAttemptStatusEnum.COMPLETED
                or attempt.result is None
            ):
                reason = getattr(attempt, "error_reason", None)
                detail = (
                    _trace_summary(getattr(attempt, "error_trace", None))
                    or (reason.name.lower().replace("_", " ") if reason is not None else None)
                )
                message = f"TLS capability {name} was incomplete"
                if detail:
                    message = f"{message}: {detail}"
                errors.append(message)
                results[name] = None
                return None
            results[name] = attempt.result
            return results[name]

        protocols = (
            ("ssl_2_0_cipher_suites", "WEB-TLS-PROTOCOL-SSL-2", "SSL 2.0 accepted"),
            ("ssl_3_0_cipher_suites", "WEB-TLS-PROTOCOL-SSL-3", "SSL 3.0 accepted"),
            ("tls_1_0_cipher_suites", "WEB-TLS-PROTOCOL-1-0", "TLS 1.0 accepted"),
            ("tls_1_1_cipher_suites", "WEB-TLS-PROTOCOL-1-1", "TLS 1.1 accepted"),
        )
        for name, rule_id, evidence in protocols:
            value = completed(name)
            if value is not None and value.accepted_cipher_suites:
                findings.append(_finding(rule_id, target, evidence))

        for name in ("tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites"):
            value = completed(name)
            if value is None:
                continue
            weak = any(
                any(
                    marker in accepted.cipher_suite.name.upper()
                    for marker in ("RC4", "3DES", "DES", "NULL", "EXPORT")
                )
                for accepted in value.accepted_cipher_suites
            )
            if weak:
                findings.append(_finding("WEB-TLS-WEAK-CIPHER", target, "Weak cipher accepted"))
                break

        certificate = completed("certificate_info")
        if certificate is not None and certificate.certificate_deployments:
            deployment = certificate.certificate_deployments[0]
            trusted = any(
                item.verified_certificate_chain for item in deployment.path_validation_results
            )
            if not trusted:
                findings.append(
                    _finding(
                        "WEB-TLS-CERTIFICATE-UNTRUSTED",
                        target,
                        "No trust store validated chain and name",
                    )
                )
            if deployment.verified_chain_has_sha1_signature:
                findings.append(
                    _finding("WEB-TLS-CERTIFICATE-SHA1", target, "SHA-1 chain signature")
                )
            if deployment.received_certificate_chain:
                leaf = deployment.received_certificate_chain[0]
                expires = leaf.not_valid_after_utc
                now = datetime.now(UTC)
                if expires <= now:
                    findings.append(
                        _finding("WEB-TLS-CERTIFICATE-EXPIRED", target, "Leaf certificate expired")
                    )
                elif expires <= now + timedelta(days=30):
                    findings.append(
                        _finding(
                            "WEB-TLS-CERTIFICATE-EXPIRING",
                            target,
                            "Leaf certificate expires within 30 days",
                        )
                    )
                public_key = leaf.public_key()
                key_size = getattr(public_key, "key_size", 0)
                key_name = type(public_key).__name__.lower()
                if ("rsa" in key_name and key_size < 2048) or (
                    "elliptic" in key_name and key_size < 224
                ):
                    findings.append(
                        _finding(
                            "WEB-TLS-CERTIFICATE-WEAK-KEY", target, "Undersized certificate key"
                        )
                    )

        simple_checks = (
            (
                "tls_compression",
                "supports_compression",
                True,
                "WEB-TLS-COMPRESSION",
                "TLS compression accepted",
            ),
            (
                "tls_fallback_scsv",
                "supports_fallback_scsv",
                False,
                "WEB-TLS-FALLBACK-SCSV-MISSING",
                "Fallback SCSV unsupported",
            ),
            (
                "heartbleed",
                "is_vulnerable_to_heartbleed",
                True,
                "WEB-TLS-HEARTBLEED",
                "Heartbleed probe vulnerable",
            ),
            (
                "openssl_ccs_injection",
                "is_vulnerable_to_ccs_injection",
                True,
                "WEB-TLS-CCS-INJECTION",
                "CCS injection probe vulnerable",
            ),
        )
        for attempt_name, attribute, expected, rule_id, evidence in simple_checks:
            value = completed(attempt_name)
            if value is not None and getattr(value, attribute) is expected:
                findings.append(_finding(rule_id, target, evidence))

        renegotiation = completed("session_renegotiation")
        if renegotiation is not None:
            if not renegotiation.supports_secure_renegotiation:
                findings.append(
                    _finding(
                        "WEB-TLS-INSECURE-RENEGOTIATION", target, "Secure renegotiation unsupported"
                    )
                )
            if renegotiation.is_vulnerable_to_client_renegotiation_dos:
                findings.append(
                    _finding(
                        "WEB-TLS-CLIENT-RENEGOTIATION-DOS",
                        target,
                        "Client renegotiation DoS probe vulnerable",
                    )
                )

        robot = completed("robot")
        if robot is not None and robot.robot_result.name.startswith("VULNERABLE"):
            findings.append(_finding("WEB-TLS-ROBOT", target, "ROBOT oracle detected"))

        unique = {finding.external_id: finding for finding in findings}
        return TlsEvidence(not errors, tuple(errors)), tuple(unique.values())


__all__ = ["TlsEvidence", "TlsScanner"]

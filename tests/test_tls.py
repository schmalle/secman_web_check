from types import SimpleNamespace

from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum

from secman_web_check.models import Severity
from secman_web_check.targets import normalize_target
from secman_web_check.tls import TlsScanner


def attempt(result):
    return SimpleNamespace(status=ScanCommandAttemptStatusEnum.COMPLETED, result=result)


def cipher_result(*names):
    return SimpleNamespace(
        accepted_cipher_suites=[
            SimpleNamespace(cipher_suite=SimpleNamespace(name=name)) for name in names
        ]
    )


def test_tls_translation_reports_legacy_protocol_weak_cipher_and_heartbleed():
    attempts = SimpleNamespace(
        ssl_2_0_cipher_suites=attempt(cipher_result()),
        ssl_3_0_cipher_suites=attempt(cipher_result()),
        tls_1_0_cipher_suites=attempt(cipher_result("TLS_RSA_WITH_3DES_EDE_CBC_SHA")),
        tls_1_1_cipher_suites=attempt(cipher_result()),
        tls_1_2_cipher_suites=attempt(cipher_result("TLS_AES_128_GCM_SHA256")),
        certificate_info=attempt(SimpleNamespace(certificate_deployments=[])),
        tls_compression=attempt(SimpleNamespace(supports_compression=False)),
        tls_fallback_scsv=attempt(SimpleNamespace(supports_fallback_scsv=True)),
        heartbleed=attempt(SimpleNamespace(is_vulnerable_to_heartbleed=True)),
        openssl_ccs_injection=attempt(SimpleNamespace(is_vulnerable_to_ccs_injection=False)),
        session_renegotiation=attempt(
            SimpleNamespace(
                supports_secure_renegotiation=True,
                is_vulnerable_to_client_renegotiation_dos=False,
            )
        ),
        robot=attempt(SimpleNamespace(robot_result=SimpleNamespace(name="NOT_VULNERABLE"))),
    )
    evidence, findings = TlsScanner()._translate(  # type: ignore[reportPrivateUsage]
        normalize_target("https://example.com"), attempts
    )
    assert evidence.complete is True
    assert {(finding.rule_id, finding.severity) for finding in findings} >= {
        ("WEB-TLS-PROTOCOL-1-0", Severity.HIGH),
        ("WEB-TLS-WEAK-CIPHER", Severity.HIGH),
        ("WEB-TLS-HEARTBLEED", Severity.CRITICAL),
    }

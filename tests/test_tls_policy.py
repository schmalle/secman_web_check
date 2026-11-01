from types import SimpleNamespace

import pytest
from sslyze import ScanCommand

from secman_web_check.config import ScannerConfig
from secman_web_check.targets import AddressDenied, normalize_target
from secman_web_check.tls import _INVENTORY_COMMANDS, _VULNERABILITY_COMMANDS, TlsScanner
from secman_web_check.tls_transport import tls_connections
from secman_web_check.traffic import TrafficController


def test_default_tls_commands_exclude_vulnerability_probes(monkeypatch):
    captured = []

    class Scanner:
        def __init__(self, **kwargs):
            assert kwargs["per_server_concurrent_connections_limit"] == 1

        def queue_scans(self, requests):
            captured.append(requests[0].scan_commands)

        def get_results(self):
            yield SimpleNamespace(scan_result=None, connectivity_error_trace=None)

    monkeypatch.setattr("secman_web_check.tls.resolve_allowed", lambda *_args: ("1.1.1.1",))
    monkeypatch.setattr("secman_web_check.tls.Scanner", Scanner)
    target = normalize_target("https://example.com")
    TlsScanner().scan(target)
    assert captured[-1] == _INVENTORY_COMMANDS
    assert ScanCommand.HEARTBLEED not in captured[-1]
    TlsScanner(ScannerConfig(tls_vulnerabilities=True)).scan(target)
    assert captured[-1] == _INVENTORY_COMMANDS | _VULNERABILITY_COMMANDS


def test_tls_hook_revalidates_every_connection_and_refuses_changed_dns(monkeypatch):
    from sslyze.connection_helpers import tls_connection

    target = normalize_target("https://example.com")
    location = SimpleNamespace(hostname=target.host, ip_address="1.1.1.1", port=443)
    monkeypatch.setattr(
        "secman_web_check.tls_transport.resolve_allowed", lambda *_args: ("2.2.2.2",)
    )
    monkeypatch.setattr(
        "secman_web_check.tls_transport.socket.create_connection",
        lambda *_args, **_kwargs: pytest.fail("DNS drift must not connect"),
    )
    original = tls_connection._open_socket_for_direct_connection
    with (
        tls_connections(target, ScannerConfig(), TrafficController(ScannerConfig())),
        pytest.raises(AddressDenied, match="DNS snapshot"),
    ):
        tls_connection._open_socket_for_direct_connection(location, 1)
    assert tls_connection._open_socket_for_direct_connection is original


def test_real_sslyze_certificate_handshakes_share_and_release_socket_leases(monkeypatch, tmp_path):
    """Exercise the actual SSLyze/Nassl socket interface against an owned TLS fixture."""
    import datetime
    import socketserver
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("fixture.example")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = tmp_path / "fixture-key.pem", tmp_path / "fixture-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            try:
                self.request.recv(1024)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = normalize_target(f"https://fixture.example:{server.server_address[1]}/")
            config = ScannerConfig(
                connect_timeout_seconds=1,
                target_timeout_seconds=15,
                requests_per_second=1000,
                global_requests_per_second=1000,
            )
            traffic = TrafficController(config)
            monkeypatch.setattr(
                "secman_web_check.tls.resolve_allowed", lambda *_args: ("127.0.0.1",)
            )
            monkeypatch.setattr(
                "secman_web_check.tls_transport.resolve_allowed", lambda *_args: ("127.0.0.1",)
            )
            monkeypatch.setattr(
                "secman_web_check.tls._INVENTORY_COMMANDS", {ScanCommand.CERTIFICATE_INFO}
            )
            _, findings = TlsScanner(config, traffic=traffic).scan(target)
            assert any(item.rule_id == "WEB-TLS-CERTIFICATE-UNTRUSTED" for item in findings)
            assert traffic.metrics()["tls"] >= 1
            assert traffic.metrics()["peak"] == 1
            assert not traffic.leases
        finally:
            server.shutdown()
            thread.join(timeout=2)

"""Exercise HTTPX/httpcore against deterministic socket-level responses."""

import socket
import ssl
import traceback
from collections import deque

import httpcore
import pytest
from httpcore._backends.base import NetworkBackend, NetworkStream

from secman_web_check.config import ScannerConfig
from secman_web_check.http import CollectionError, HttpCollector, PinnedNetworkBackend
from secman_web_check.targets import AddressDenied, normalize_target


def response(status=200, headers=(), body=b"ok"):
    fields = [("Content-Length", str(len(body))), *headers]
    return (
        f"HTTP/1.1 {status} Response\r\n".encode()
        + b"".join(f"{key}: {value}\r\n".encode() for key, value in fields)
        + b"\r\n"
        + body
    )


class FakeStream(NetworkStream):
    def __init__(self, payload, backend):
        self.payload = payload
        self.backend = backend
        self.written = b""
        self.closed = False
        self.bytes_read = 0

    def read(self, max_bytes, timeout=None):
        data, self.payload = self.payload[:max_bytes], self.payload[max_bytes:]
        self.bytes_read += len(data)
        return data

    def write(self, buffer, timeout=None):
        self.written += buffer

    def close(self):
        self.closed = True

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.backend.tls.append(
            (server_hostname, ssl_context.check_hostname, ssl_context.verify_mode)
        )
        return self


class FakeBackend(NetworkBackend):
    def __init__(self, *payloads, failing=()):
        self.payloads = deque(payloads)
        self.failing = failing
        self.dials = []
        self.tls = []
        self.streams = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dials.append((host, port, timeout))
        if host in self.failing:
            raise httpcore.ConnectError("sensitive upstream error")
        stream = FakeStream(self.payloads.popleft(), self)
        self.streams.append(stream)
        return stream


def make_collector(backend, addresses=None, **config):
    calls = []

    def resolve(host, port, *args):
        calls.append(host)
        values = (addresses or {}).get(host, [host if host == "127.0.0.1" else "93.184.216.34"])
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, port)) for value in values]

    return HttpCollector(ScannerConfig(**config), resolver=resolve, network_backend=backend), calls


def test_transport_dials_approved_ip_and_preserves_host_and_verified_tls(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    backend = FakeBackend(response())
    collector, calls = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com:8443/path"))[-1]
    assert [dial[:2] for dial in backend.dials] == [("93.184.216.34", 8443)]
    assert backend.tls == [("example.com", True, ssl.CERT_REQUIRED)]
    assert b"Host: example.com:8443\r\n" in backend.streams[0].written
    assert b"Accept-Encoding: identity\r\n" in backend.streams[0].written
    assert calls == ["example.com"]
    assert result.body == b"ok"
    assert result.elapsed_seconds >= 0
    assert backend.streams[0].closed


def test_redirect_destination_is_checked_before_second_request():
    backend = FakeBackend(response(302, [("Location", "https://127.0.0.1/admin")]))
    collector, calls = make_collector(backend)
    with pytest.raises(AddressDenied):
        collector.collect(normalize_target("https://example.com"))
    assert len(backend.dials) == 1
    assert calls == ["example.com", "127.0.0.1"]


def test_same_host_redirect_resolves_again_and_blocks_rebinding():
    backend = FakeBackend(response(302, [("Location", "/next")]))
    answers = iter(["93.184.216.34", "127.0.0.1"])

    def resolver(host, port, *args):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers), port))]

    collector = HttpCollector(resolver=resolver, network_backend=backend)
    with pytest.raises(AddressDenied):
        collector.collect(normalize_target("https://example.com"))
    assert len(backend.dials) == 1


def test_redirect_upgrade_and_cross_host_chain():
    backend = FakeBackend(response(301, [("Location", "https://other.example/next")]), response())
    collector, calls = make_collector(backend, {"other.example": ["1.1.1.1"]})
    results = collector.collect(normalize_target("http://example.com"))
    assert calls == ["example.com", "other.example"]
    assert [dial[:2] for dial in backend.dials] == [("93.184.216.34", 80), ("1.1.1.1", 443)]
    assert results[0].redirect_url == results[1].url == "https://other.example/next"
    assert results[0].url == "http://example.com/"
    assert backend.tls == [("other.example", True, ssl.CERT_REQUIRED)]


def test_downgrade_is_recorded_but_never_followed():
    backend = FakeBackend(response(302, [("Location", "http://other.example/")]))
    collector, calls = make_collector(backend)
    results = collector.collect(normalize_target("https://example.com"))
    assert len(backend.dials) == 1
    assert calls == ["example.com"]
    assert results[-1].redirect_url == "http://other.example/"
    assert results[-1].blocked_redirect_reason == "HTTPS downgrade"


@pytest.mark.parametrize(
    "location", [None, "", "ftp://other.example/", "https://u:secret@x/", "//[bad"]
)
def test_invalid_redirect_is_recorded_without_leaking_location(location):
    headers = [] if location is None else [("Location", location)]
    backend = FakeBackend(response(302, headers))
    collector, _ = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com"))[-1]
    assert result.blocked_redirect_reason
    assert "secret" not in repr(result)
    assert len(backend.dials) == 1


def test_redirect_limit_stops_loop_and_records_reason():
    backend = FakeBackend(*(response(302, [("Location", "/")]) for _ in range(2)))
    collector, _ = make_collector(backend, max_redirects=1)
    results = collector.collect(normalize_target("https://example.com"))
    assert len(results) == 2
    assert results[-1].blocked_redirect_reason == "Redirect limit reached"
    assert len(backend.dials) == 2


@pytest.mark.parametrize(
    "size,truncated", [(0, False), (1023, False), (1024, False), (1025, True), (100_000, True)]
)
def test_body_is_bounded_and_stream_closed(size, truncated):
    backend = FakeBackend(response(body=b"x" * size))
    collector, _ = make_collector(backend, max_body_bytes=1024)
    result = collector.collect(normalize_target("https://example.com"))[-1]
    assert result.body == b"x" * min(size, 1024)
    assert result.truncated is truncated
    assert backend.streams[0].closed
    assert backend.streams[0].bytes_read < 70_000


def test_compressed_response_is_not_decompressed():
    import gzip

    compressed = gzip.compress(b"x" * 1_000_000)
    backend = FakeBackend(response(headers=[("Content-Encoding", "gzip")], body=compressed))
    collector, _ = make_collector(backend, max_body_bytes=1024)
    with pytest.raises(CollectionError, match="encoding"):
        collector.collect(normalize_target("https://example.com"))
    assert backend.streams[0].closed


def test_failover_uses_only_preapproved_addresses():
    backend = FakeBackend(response(), failing=["93.184.216.34"])
    collector, calls = make_collector(backend, {"example.com": ["93.184.216.34", "1.1.1.1"]})
    collector.collect(normalize_target("https://example.com"))
    assert [dial[0] for dial in backend.dials] == ["93.184.216.34", "1.1.1.1"]
    assert calls == ["example.com"]


def test_backend_rejects_unpinned_host_or_port():
    backend = FakeBackend(response())
    pinned = PinnedNetworkBackend(normalize_target("https://example.com"), ("1.1.1.1",), backend)
    with pytest.raises(AddressDenied):
        pinned.connect_tcp("other.example", 443)
    with pytest.raises(AddressDenied):
        pinned.connect_tcp("example.com", 80)
    assert backend.dials == []


def test_cookie_values_redacted_duplicate_headers_preserved_and_no_cookie_replay():
    backend = FakeBackend(
        response(
            302,
            [
                ("Set-Cookie", "session=secret-one; Secure; HttpOnly"),
                ("Set-Cookie", "second=secret-two; Path=/"),
                ("Location", "/next"),
            ],
        ),
        response(),
    )
    collector, _ = make_collector(backend)
    results = collector.collect(normalize_target("https://example.com"))
    cookies = [v for k, v in results[0].headers if k.lower() == "set-cookie"]
    assert cookies == ["session=<redacted>; Secure; HttpOnly", "second=<redacted>; Path=/"]
    assert "secret-one" not in repr(results)
    assert "secret-two" not in repr(results)
    assert b"Cookie:" not in backend.streams[1].written


@pytest.mark.parametrize(
    "header", ["Authorization", "Cookie", "Proxy-Authorization", "Host", "X-API-Key"]
)
def test_sensitive_or_host_override_headers_rejected_without_echo(header):
    backend = FakeBackend(response())
    collector, _ = make_collector(backend)
    secret_headers = {header: "secret-value"}
    with pytest.raises(CollectionError) as error:
        collector.collect(normalize_target("https://example.com"), headers=secret_headers)
    assert "secret-value" not in "".join(traceback.format_exception(error.value))
    assert backend.dials == []


def test_safe_probe_headers_and_method_are_recorded():
    backend = FakeBackend(response())
    collector, _ = make_collector(backend)
    result = collector.collect(
        normalize_target("https://example.com"),
        method="OPTIONS",
        headers={"Origin": "https://scanner.invalid"},
    )[-1]
    assert result.request.method == "OPTIONS"
    assert ("origin", "https://scanner.invalid") in result.request.headers
    assert b"OPTIONS / HTTP/1.1" in backend.streams[0].written


def test_transport_failure_hides_upstream_message_and_query():
    backend = FakeBackend(failing=["93.184.216.34"])
    collector, _ = make_collector(backend)
    target = normalize_target("https://example.com/?token=secret-query")
    with pytest.raises(CollectionError) as error:
        collector.collect(target)
    formatted = "".join(traceback.format_exception(error.value))
    assert "sensitive upstream error" not in formatted
    assert "secret-query" not in formatted


def test_mixed_dns_answers_are_denied_before_any_connection():
    backend = FakeBackend(response())
    collector, _ = make_collector(backend, {"example.com": ["1.1.1.1", "127.0.0.1"]})
    with pytest.raises(AddressDenied):
        collector.collect(normalize_target("https://example.com"))
    assert backend.dials == []


def test_duplicate_locations_do_not_choose_an_arbitrary_destination():
    backend = FakeBackend(response(302, [("Location", "/one"), ("Location", "/two")]))
    collector, _ = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com"))[-1]
    assert result.blocked_redirect_reason == "Missing or invalid redirect location"
    assert len([name for name, _ in result.headers if name == "location"]) == 2
    assert len(backend.dials) == 1


def test_control_characters_in_location_are_not_silently_normalized():
    backend = FakeBackend(response(302, [("Location", "https://other.example/\tpath")]))
    collector, _ = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com"))[-1]
    assert result.blocked_redirect_reason == "Missing or invalid redirect location"
    assert len(backend.dials) == 1


def test_oversized_headers_fail_before_body_collection():
    backend = FakeBackend(response(headers=[("X-Large", "x" * 70_000)]))
    collector, _ = make_collector(backend)
    with pytest.raises(CollectionError):
        collector.collect(normalize_target("https://example.com"))
    assert backend.streams[0].closed


def test_chunked_body_is_bounded_without_content_length():
    payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    payload += b"800\r\n" + b"x" * 2048 + b"\r\n0\r\n\r\n"
    backend = FakeBackend(payload)
    collector, _ = make_collector(backend)
    limited = collector.with_max_body_bytes(1024)
    result = limited.collect(normalize_target("https://example.com"))[-1]
    assert result.body == b"x" * 1024
    assert result.truncated
    assert collector.config.max_body_bytes == 1_048_576


def test_query_values_removed_from_evidence_but_request_still_uses_query():
    backend = FakeBackend(response(302, [("Location", "http://example.com/?key=sensitive")]))
    collector, _ = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com/?key=sensitive"))[-1]
    assert "sensitive" not in repr(result)
    assert b"GET /?key=sensitive HTTP/1.1" in backend.streams[0].written


def test_read_error_does_not_expose_response_headers():
    # An incomplete declared body fails inside the real httpcore response stream.
    backend = FakeBackend(b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\nSet-Cookie: s=secret\r\n\r\nx")
    collector, _ = make_collector(backend)
    with pytest.raises(CollectionError) as error:
        collector.collect(normalize_target("https://example.com"))
    assert "secret" not in str(error.value)
    assert backend.streams[0].closed


@pytest.mark.parametrize("addresses", [(), ("example.com",)])
def test_backend_rejects_empty_or_nonliteral_pin(addresses):
    with pytest.raises(AddressDenied):
        PinnedNetworkBackend(normalize_target("https://example.com"), addresses)


def test_backend_cannot_dial_unix_socket():
    backend = PinnedNetworkBackend(normalize_target("https://example.com"), ("1.1.1.1",))
    with pytest.raises(AddressDenied):
        backend.connect_unix_socket("/tmp/scanner-test.sock")


def test_unsafe_method_and_header_injection_fail_before_network():
    backend = FakeBackend(response())
    collector, _ = make_collector(backend)
    target = normalize_target("https://example.com")
    with pytest.raises(CollectionError):
        collector.collect(target, method="POST")
    with pytest.raises(CollectionError):
        collector.collect(target, headers={"Origin": "https://scanner.invalid\r\nCookie: fake"})
    assert backend.dials == []


@pytest.mark.parametrize(
    "name",
    [
        "X-API-Key",
        "api-key",
        "X-Auth-Token",
        "x-access-token",
        "X-Amz-Security-Token",
        "Authentication-Info",
        "Proxy-Authentication-Info",
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "X-Service-API-Key",
        "X-Service-Auth-Token",
        "X-Service-Access-Token",
        "X-Service-Security-Token",
        "X-Service-Refresh-Token",
    ],
)
def test_credential_response_headers_are_redacted_in_evidence(name):
    backend = FakeBackend(response(headers=[(name, "response-credential-sentinel")]))
    collector, _ = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com"))[-1]
    assert (name.lower(), "<redacted>") in result.headers
    assert "response-credential-sentinel" not in repr(result)


def test_credential_suffixes_preserve_noncredential_security_headers():
    headers = [
        ("X-Token-Policy", "strict"),
        ("Public-Key-Pins-Report-Only", "max-age=60"),
        ("X-Key-ID", "public-identifier"),
        ("X-Auth-Token-Lifetime", "60"),
    ]
    backend = FakeBackend(response(headers=headers))
    collector, _ = make_collector(backend)
    result = collector.collect(normalize_target("https://example.com"))[-1]
    assert all((name.lower(), value) in result.headers for name, value in headers)

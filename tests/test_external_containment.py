import hashlib
import http.client
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from secman_web_check.external_profile import confined_run, load_external_profile, verified_copy
from secman_web_check.external_proxy import scoped_proxy
from secman_web_check.external_scanners import scan_with_external
from secman_web_check.targets import AddressPolicy, normalize_target


def profile(tmp_path):
    binary, asset = tmp_path / "engine", tmp_path / "template.yaml"
    binary.write_bytes(b"synthetic executable")
    asset.write_bytes(b"id: synthetic-template")
    doc = {
        "version": 1,
        "engines": {
            "nuclei": {
                "path": str(binary),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "version": "fixture",
                "reviewedReadOnly": True,
                "assets": [
                    {"path": str(asset), "sha256": hashlib.sha256(asset.read_bytes()).hexdigest()}
                ],
            }
        },
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(doc))
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_external_profile_and_assets_fail_closed_on_tampering_or_missing_review(tmp_path):
    path, digest = profile(tmp_path)
    approved = load_external_profile(path, digest)
    assert approved.provenance()["engines"]["nuclei"]["version"] == "fixture"
    entry = approved.entry("nuclei")
    Path(entry["path"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        verified_copy(entry, tmp_path / "copy")
    with pytest.raises(ValueError, match="checksum"):
        load_external_profile(path, "a" * 64)
    doc = json.loads(path.read_text())
    doc["engines"]["nuclei"]["reviewedReadOnly"] = False
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="reviewed read-only"):
        load_external_profile(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_external_scan_refuses_unpinned_or_nonroot_input_without_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "secman_web_check.external_scanners.scoped_proxy",
        lambda *_args: pytest.fail("should not launch"),
    )
    result = scan_with_external(
        normalize_target("https://example.com/"), ("nuclei",), policy=AddressPolicy()
    )
    assert result.errors
    approved = load_external_profile(*profile(tmp_path))
    result = scan_with_external(
        normalize_target("https://example.com/app/"),
        ("nuclei",),
        policy=AddressPolicy(),
        profile=approved,
    )
    assert "origin-root" in result.errors[0]


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.append(self.path)
        self.send_response(200)
        self.send_header("content-length", "7")
        self.end_headers()
        self.wfile.write(b"fixture")

    def log_message(self, *_args):
        pass


@pytest.fixture
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scope_proxy_forwards_only_approved_origin_and_blocks_methods_and_redirect_hosts(
    monkeypatch, upstream
):
    port = upstream.server_port
    target = normalize_target(f"http://approved.example:{port}/")
    lookups = []

    def resolve(value, _policy):
        lookups.append(value.host)
        return ("127.0.0.1",)  # injected fixture endpoint, never a production policy override

    monkeypatch.setattr("secman_web_check.external_proxy.resolve_allowed", resolve)
    with scoped_proxy(target, AddressPolicy(), None, 5) as proxy_port:

        def fetch(method, url):
            conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=2)
            conn.request(method, url)
            response = conn.getresponse()
            status = response.status
            response.read()
            conn.close()
            return status

        assert fetch("GET", f"http://approved.example:{port}/fixture") == 200
        assert fetch("GET", f"http://outside.example:{port}/leak") == 403
        assert fetch("POST", f"http://approved.example:{port}/write") == 403
    assert upstream.paths == ["/fixture"]
    assert lookups == ["approved.example"]


@pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("SECMAN_TEST_SANDBOX") != "1",
    reason="requires native macOS sandbox outside the harness sandbox; run separately",
)
def test_native_sandbox_denies_direct_egress_and_allows_only_scope_proxy(
    monkeypatch, upstream, tmp_path
):
    target = normalize_target(f"http://approved.example:{upstream.server_port}/")
    monkeypatch.setattr(
        "secman_web_check.external_proxy.resolve_allowed", lambda *_args: ("127.0.0.1",)
    )
    output = tmp_path / "result.json"
    with scoped_proxy(target, AddressPolicy(), None, 10) as port:
        with pytest.raises(RuntimeError, match="confinement"):
            confined_run(
                [
                    "/usr/bin/curl",
                    "--noproxy",
                    "*",
                    "--max-time",
                    "2",
                    "-o",
                    str(output),
                    f"http://127.0.0.1:{upstream.server_port}/denied",
                ],
                output,
                5,
                port,
                (),
            )
        assert upstream.paths == []
        confined_run(
            [
                "/usr/bin/curl",
                "--noproxy",
                "",
                "--proxy",
                f"http://127.0.0.1:{port}",
                "--max-time",
                "2",
                "-o",
                str(output),
                target.url + "allowed",
            ],
            output,
            5,
            port,
            (),
        )
        assert upstream.paths == ["/allowed"]
        assert output.read_bytes() == b"fixture"


def test_proxy_validates_ipv6_custom_port_before_dialing_and_pins_literal(monkeypatch):
    target = normalize_target("https://[fd00::1234]:9443/")
    calls = []
    monkeypatch.setattr(
        "secman_web_check.external_proxy.resolve_allowed", lambda *_args: ("fd00::1234",)
    )
    original = socket.create_connection

    def connection(address, **kwargs):
        if address[0] == "127.0.0.1":
            return original(address, **kwargs)
        calls.append(address)
        raise OSError("fixture refuses actual remote connection")

    monkeypatch.setattr("secman_web_check.external_proxy.socket.create_connection", connection)
    with scoped_proxy(target, AddressPolicy(allow_private=True), None, 5) as port:
        for destination in ("[fd00::1234]:9444", "[fd00::1234]:9443"):
            with original(("127.0.0.1", port), timeout=2) as client:
                client.sendall(f"CONNECT {destination} HTTP/1.1\r\n\r\n".encode())
                assert b"403" in client.recv(4096)
    assert calls == [("fd00::1234", 9443)]

import ipaddress
import socket
from pathlib import Path

import pytest

from secman_web_check.config import ScannerConfig
from secman_web_check.models import TargetResult, TargetStatus
from secman_web_check.targets import (
    AddressDenied,
    AddressPolicy,
    TargetError,
    load_targets,
    normalize_target,
    resolve_allowed,
)


@pytest.mark.parametrize(
    "value",
    [
        "http://user:pass@example.com",
        "file:///etc/passwd",
        "https://example.com/#secret",
    ],
)
def test_rejects_unsafe_target_forms(value: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(value)


def test_normalizes_idna_scheme_default_port_and_path() -> None:
    target = normalize_target("HTTP://BÜCHER.example:80/reports?format=json")

    assert target.url == "http://xn--bcher-kva.example/reports?format=json"
    assert target.scheme == "http"
    assert target.host == "xn--bcher-kva.example"
    assert target.port is None


def test_uses_https_when_a_target_has_no_scheme() -> None:
    target = normalize_target("Example.COM:8443/status")

    assert target.url == "https://example.com:8443/status"
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 8443


def test_load_targets_skips_comments_and_preserves_first_normalized_url(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text("\n# approved targets\nHTTP://EXAMPLE.COM:80/\nexample.com\n", encoding="utf-8")

    loaded = load_targets("https://example.com/", path)

    assert tuple(target.url for target in loaded.targets) == (
        "https://example.com/",
        "http://example.com/",
    )
    assert loaded.skipped == ()


def test_load_targets_skips_invalid_lines_without_strict(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text(
        "example.com\nftp://unsupported.example\nother.example:8080/status\n",
        encoding="utf-8",
    )

    loaded = load_targets(None, path)

    assert tuple(target.url for target in loaded.targets) == (
        "https://example.com/",
        "https://other.example:8080/status",
    )
    assert [skipped.value for skipped in loaded.skipped] == ["ftp://unsupported.example"]
    assert "scheme" in loaded.skipped[0].reason


def test_load_targets_strict_raises_on_the_first_invalid_line(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text("example.com\nftp://unsupported.example\n", encoding="utf-8")

    with pytest.raises(TargetError, match="scheme"):
        load_targets(None, path, strict=True)


def test_load_targets_csv_retains_validated_aws_account_numbers(tmp_path: Path) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(
        "awsAccountNumber,target\n"
        "111122223333,example.com\n"
        "444455556666,https://other.example/path\n"
        "123456789,short-account.example\n",
        encoding="utf-8",
    )

    loaded = load_targets(None, None, path)

    assert [(target.aws_account_number, target.url) for target in loaded.targets] == [
        ("111122223333", "https://example.com/"),
        ("444455556666", "https://other.example/path"),
        ("123456789", "https://short-account.example/"),
    ]
    assert loaded.skipped == ()


def test_load_targets_csv_splits_whitespace_separated_targets(tmp_path: Path) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(
        "awsAccountNumber,target\n111122223333,example.com  other.example\n",
        encoding="utf-8",
    )

    loaded = load_targets(None, None, path)

    assert [(target.aws_account_number, target.url) for target in loaded.targets] == [
        ("111122223333", "https://example.com/"),
        ("111122223333", "https://other.example/"),
    ]
    assert loaded.skipped == ()


def test_load_targets_csv_skips_only_an_invalid_split_target_without_strict(
    tmp_path: Path,
) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(
        "awsAccountNumber,target\n111122223333,example.com ftp://unsupported.example\n",
        encoding="utf-8",
    )

    loaded = load_targets(None, None, path)

    assert [(target.aws_account_number, target.url) for target in loaded.targets] == [
        ("111122223333", "https://example.com/"),
    ]
    assert len(loaded.skipped) == 1
    assert loaded.skipped[0].value == "ftp://unsupported.example"


@pytest.mark.parametrize(
    "content",
    [
        "account,target\n111122223333,example.com\n",
        "AWS Account Number,TARGET\n111122223333,example.com\n",
        "awsAccountNumber,target\n123,example.com\n",
        "awsAccountNumber,target\n12345678,example.com\n",
        "awsAccountNumber,target\n1234567890123,example.com\n",
        "awsAccountNumber,target\n111122223333,\n",
        "awsAccountNumber,target\n111122223333,example.com,extra\n",
    ],
)
def test_load_targets_csv_rejects_malformed_rows(tmp_path: Path, content: str) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(TargetError):
        load_targets(None, None, path, strict=True)


def test_load_targets_csv_skips_malformed_rows_without_strict(tmp_path: Path) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(
        "awsAccountNumber,target\n"
        "123,bad-account.example\n"
        "111122223333,example.com\n"
        "222233334444,\n"
        "555566667777,other.example,extra\n",
        encoding="utf-8",
    )

    loaded = load_targets(None, None, path)

    assert tuple(target.url for target in loaded.targets) == ("https://example.com/",)
    assert [skipped.reason for skipped in loaded.skipped] == [
        "target CSV row 2 has an invalid AWS account number",
        "target CSV row 4 has an empty target",
        "target CSV row 5 has too many columns",
    ]


def test_load_targets_csv_rejects_a_bad_header_even_without_strict(tmp_path: Path) -> None:
    path = tmp_path / "targets.csv"
    path.write_text("account,target\n111122223333,example.com\n", encoding="utf-8")

    with pytest.raises(TargetError, match="header"):
        load_targets(None, None, path)


def test_load_targets_csv_rejects_one_target_assigned_to_two_accounts(tmp_path: Path) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(
        "awsAccountNumber,target\n111122223333,example.com\n444455556666,EXAMPLE.COM\n",
        encoding="utf-8",
    )

    with pytest.raises(TargetError, match="more than one AWS account"):
        load_targets(None, None, path, strict=True)


def test_load_targets_csv_skips_a_conflicting_second_account_without_strict(
    tmp_path: Path,
) -> None:
    path = tmp_path / "targets.csv"
    path.write_text(
        "awsAccountNumber,target\n111122223333,example.com\n444455556666,EXAMPLE.COM\n",
        encoding="utf-8",
    )

    loaded = load_targets(None, None, path)

    assert [(target.aws_account_number, target.url) for target in loaded.targets] == [
        ("111122223333", "https://example.com/"),
    ]
    assert "more than one AWS account" in loaded.skipped[0].reason


def test_private_addresses_require_opt_in() -> None:
    target = normalize_target("https://internal.example")
    resolver = lambda *_: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))]

    with pytest.raises(AddressDenied):
        resolve_allowed(target, AddressPolicy(), resolver)
    assert resolve_allowed(target, AddressPolicy(allow_private=True), resolver) == ("10.1.2.3",)


def test_loopback_remains_denied_with_private_opt_in() -> None:
    assert not AddressPolicy(allow_private=True).allows(ipaddress.ip_address("127.0.0.1"))


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "192.0.2.1", "::1", "fe80::1"],
)
def test_private_opt_in_never_allows_special_use_addresses(address: str) -> None:
    assert not AddressPolicy(allow_private=True).allows(ipaddress.ip_address(address))


def test_private_opt_in_allows_only_rfc1918_and_ula_addresses() -> None:
    policy = AddressPolicy(allow_private=True)

    assert policy.allows(ipaddress.ip_address("192.168.1.1"))
    assert policy.allows(ipaddress.ip_address("fd12:3456::1"))
    assert not policy.allows(ipaddress.ip_address("100.64.0.1"))


@pytest.mark.parametrize(
    "address",
    ["192.0.0.9", "192.0.0.10", "192.31.196.1", "192.88.99.1", "2001:1::1"],
)
def test_private_opt_in_denies_iana_special_purpose_addresses(address: str) -> None:
    assert not AddressPolicy(allow_private=True).allows(ipaddress.ip_address(address))


@pytest.mark.parametrize(
    ("address", "allowed"),
    [("::ffff:10.1.2.3", True), ("::ffff:192.0.0.9", False)],
)
def test_ipv4_mapped_ipv6_uses_the_ipv4_policy(address: str, allowed: bool) -> None:
    assert AddressPolicy(allow_private=True).allows(ipaddress.ip_address(address)) is allowed


def test_resolution_rejects_a_mixed_safe_and_private_answer_set() -> None:
    target = normalize_target("https://mixed.example")
    resolver = lambda *_: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443)),
    ]

    with pytest.raises(AddressDenied):
        resolve_allowed(target, AddressPolicy(), resolver)


@pytest.mark.parametrize(
    "address",
    ["192.0.0.9", "192.0.0.10", "192.31.196.1", "192.88.99.1", "2001:1::1"],
)
def test_resolution_rejects_iana_special_purpose_answers(address: str) -> None:
    target = normalize_target("https://special-purpose.example")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    resolver = lambda *_: [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    with pytest.raises(AddressDenied):
        resolve_allowed(target, AddressPolicy(allow_private=True), resolver)


def test_resolution_deduplicates_allowed_answers_in_order() -> None:
    target = normalize_target("https://public.example")
    resolver = lambda *_: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
    ]

    assert resolve_allowed(target, AddressPolicy(), resolver) == (
        "8.8.8.8",
        "2606:4700:4700::1111",
    )


def test_address_policy_uses_scanner_private_target_setting() -> None:
    policy = AddressPolicy.from_config(ScannerConfig(allow_private_targets=True))

    assert policy.allows(ipaddress.ip_address("10.1.2.3"))


def test_target_results_accept_immutable_normalized_targets() -> None:
    result = TargetResult(normalize_target("example.com"), TargetStatus.SUCCESS)

    assert result.target.url == "https://example.com/"

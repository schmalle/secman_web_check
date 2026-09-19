"""Target normalization and address policy for scanner network boundaries."""

from __future__ import annotations

import csv
import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .config import ScannerConfig

_EXPLICIT_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_ULA_NETWORK = ipaddress.IPv6Network("fc00::/7")

# IANA IPv4/IPv6 Special-Purpose Address Registries, snapshot 2026-09-10.
# RFC1918 and ULA ranges are deliberately excluded: allow_private controls them below.
_IANA_IPV4_SPECIAL_PURPOSE_DENY_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.31.196.0/24"),
    ipaddress.IPv4Network("192.52.193.0/24"),
    ipaddress.IPv4Network("192.88.99.0/24"),
    ipaddress.IPv4Network("192.175.48.0/24"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)
_IANA_IPV6_SPECIAL_PURPOSE_DENY_NETWORKS = (
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("100:0:0:1::/64"),
    ipaddress.IPv6Network("2001::/23"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("2002::/16"),
    ipaddress.IPv6Network("2620:4f:8000::/48"),
    ipaddress.IPv6Network("3fff::/20"),
    ipaddress.IPv6Network("5f00::/16"),
    ipaddress.IPv6Network("fec0::/10"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
)


class TargetError(ValueError):
    """Raised when a supplied scan target is not a supported HTTP URL."""


class AddressDenied(TargetError):
    """Raised when DNS resolution returns an address outside scanner policy."""


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    """A canonical HTTP target safe to pass to later scanner stages."""

    url: str
    scheme: str
    host: str
    port: int | None
    aws_account_number: str | None = None
    secman_subject_id: int | None = None
    secman_asset_id: int | None = None


@dataclass(frozen=True, slots=True)
class SkippedTarget:
    """An input line rejected while loading targets in non-strict mode."""

    value: str
    reason: str


@dataclass(frozen=True, slots=True)
class LoadedTargets:
    """Normalized targets plus any input lines skipped in non-strict mode."""

    targets: tuple[NormalizedTarget, ...]
    skipped: tuple[SkippedTarget, ...]


@dataclass(frozen=True, slots=True)
class AddressPolicy:
    """Permit public IP addresses and optionally RFC1918/ULA addresses."""

    allow_private: bool = False

    @classmethod
    def from_config(cls, config: ScannerConfig) -> AddressPolicy:
        """Create the address policy selected by scanner configuration."""
        return cls(allow_private=config.allow_private_targets)

    def allows(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return whether an address is eligible for an outbound scanner connection."""
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            return self.allows(address.ipv4_mapped)
        if isinstance(address, ipaddress.IPv4Address) and any(
            address in network for network in _RFC1918_NETWORKS
        ):
            return self.allow_private
        if isinstance(address, ipaddress.IPv6Address) and address in _ULA_NETWORK:
            return self.allow_private
        if isinstance(address, ipaddress.IPv4Address) and any(
            address in network for network in _IANA_IPV4_SPECIAL_PURPOSE_DENY_NETWORKS
        ):
            return False
        if isinstance(address, ipaddress.IPv6Address) and any(
            address in network for network in _IANA_IPV6_SPECIAL_PURPOSE_DENY_NETWORKS
        ):
            return False
        return address.is_global


def normalize_target(value: str) -> NormalizedTarget:
    """Validate and canonicalize one scanner target URL."""
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        raise TargetError("target must be a non-empty URL without whitespace")

    candidate = value if _EXPLICIT_SCHEME.match(value) else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise TargetError("target has an invalid port") from error

    if parsed.scheme not in {"http", "https"}:
        raise TargetError("target scheme must be http or https")
    if not parsed.netloc or parsed.hostname is None:
        raise TargetError("target must include a host")
    if "@" in parsed.netloc:
        raise TargetError("target must not include user information")
    if parsed.fragment:
        raise TargetError("target must not include a fragment")

    scheme = parsed.scheme.lower()
    host = _normalize_host(parsed.hostname)
    if port in {80 if scheme == "http" else 443}:
        port = None

    path = parsed.path or "/"
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    url = urlunsplit(SplitResult(scheme, netloc, path, parsed.query, ""))
    return NormalizedTarget(url=url, scheme=scheme, host=host, port=port)


def load_targets(
    single: str | None,
    file: Path | None,
    csv_file: Path | None = None,
    *,
    strict: bool = False,
) -> LoadedTargets:
    """Load unique normalized targets from one supported input source.

    Strict mode raises on the first invalid input line. Otherwise invalid
    lines are skipped and recorded in ``LoadedTargets.skipped``.
    """
    skipped: list[SkippedTarget] = []
    values: list[tuple[str, str | None]] = []
    if single is not None:
        values.append((single, None))
    if file is not None:
        for line in file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                values.append((stripped, None))
    if csv_file is not None:
        values.extend(_load_csv_values(csv_file, strict=strict, skipped=skipped))

    targets: list[NormalizedTarget] = []
    seen: dict[str, str | None] = {}
    for value, aws_account_number in values:
        try:
            target = replace(normalize_target(value), aws_account_number=aws_account_number)
        except TargetError as error:
            if strict:
                raise
            skipped.append(SkippedTarget(value=value, reason=str(error)))
            continue
        previous_account = seen.get(target.url)
        if target.url in seen and previous_account != aws_account_number:
            reason = f"target {target.url} is assigned to more than one AWS account"
            if strict:
                raise TargetError(reason)
            skipped.append(SkippedTarget(value=value, reason=reason))
            continue
        if target.url not in seen:
            seen[target.url] = aws_account_number
            targets.append(target)
    return LoadedTargets(targets=tuple(targets), skipped=tuple(skipped))


def _load_csv_values(
    path: Path,
    *,
    strict: bool,
    skipped: list[SkippedTarget],
) -> list[tuple[str, str]]:
    """Read AWS account and target pairs from a header-based CSV file."""
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["awsAccountNumber", "target"]:
            raise TargetError("target CSV header must be exactly awsAccountNumber,target")

        values: list[tuple[str, str]] = []
        for line_number, row in enumerate(reader, start=2):
            account = (row.get("awsAccountNumber") or "").strip()
            target = (row.get("target") or "").strip()
            reason: str | None = None
            if None in row:
                reason = f"target CSV row {line_number} has too many columns"
            elif not re.fullmatch(r"[0-9]{9,12}", account):
                reason = f"target CSV row {line_number} has an invalid AWS account number"
            elif not target:
                reason = f"target CSV row {line_number} has an empty target"
            if reason is not None:
                if strict:
                    raise TargetError(reason)
                skipped.append(SkippedTarget(value=target, reason=reason))
                continue
            values.extend((candidate, account) for candidate in target.split())
    return values


def resolve_allowed(
    target: NormalizedTarget,
    policy: AddressPolicy,
    resolver: Callable[..., object] = socket.getaddrinfo,
) -> tuple[str, ...]:
    """Resolve a target only when every DNS answer is allowed by policy."""
    port = target.port if target.port is not None else (443 if target.scheme == "https" else 80)
    answers = cast(
        list[tuple[object, object, int, str, tuple[str, ...]]],
        resolver(target.host, port, socket.AF_UNSPEC, socket.SOCK_STREAM),
    )
    if not answers:
        raise AddressDenied(f"target {target.host} did not resolve to an address")

    addresses: list[str] = []
    for answer in answers:
        value = answer[4][0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise AddressDenied(f"target {target.host} resolved to an invalid address") from error
        if not policy.allows(address):
            raise AddressDenied(f"target {target.host} resolved to a denied address")
        normalized = str(address)
        if normalized not in addresses:
            addresses.append(normalized)
    return tuple(addresses)


def _normalize_host(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if any(character in host for character in "/\\@"):
        raise TargetError("target host is invalid")
    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise TargetError("target host is invalid") from error
    if not normalized or any(
        character.isspace() or ord(character) < 32 for character in normalized
    ):
        raise TargetError("target host is invalid")
    return normalized

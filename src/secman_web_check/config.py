"""Configuration loading with explicit CLI, environment, TOML, default precedence."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path

_PREFIX = "SECMAN_WEB_CHECK_"


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    concurrency: int = 4
    active: bool = False
    allow_private_targets: bool = False
    max_body_bytes: int = 1_048_576
    max_redirects: int = 5
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 20.0

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.max_body_bytes < 1:
            raise ValueError("max_body_bytes must be at least 1")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must not be negative")
        if self.connect_timeout_seconds <= 0 or self.read_timeout_seconds <= 0:
            raise ValueError("timeouts must be positive")


def _parse_bool(value: object, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "1", "yes", "on"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _coerce(name: str, value: object) -> bool | int | float:
    if name in {"active", "allow_private_targets"}:
        return _parse_bool(value, name)
    if name in {"concurrency", "max_body_bytes", "max_redirects"}:
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return int(value)
        raise ValueError(f"{name} must be an integer")
    if name in {"connect_timeout_seconds", "read_timeout_seconds"}:
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return float(value)
        raise ValueError(f"{name} must be a number")
    raise ValueError(f"unknown scanner configuration key: {name}")


def _toml_values(config_path: Path | None) -> dict[str, object]:
    if config_path is None:
        return {}
    with config_path.open("rb") as config_file:
        document = tomllib.load(config_file)
    scan = document.get("scan", {})
    if not isinstance(scan, dict):
        raise TypeError("[scan] must be a TOML table")
    return scan


def load_config(
    config_path: Path | None,
    environ: Mapping[str, str],
    **overrides: object,
) -> ScannerConfig:
    """Load configuration, preferring explicit CLI values over environment and TOML."""
    names = {item.name for item in fields(ScannerConfig)}
    values = _toml_values(config_path)
    unknown_toml = set(values) - names
    unknown_overrides = set(overrides) - names
    if unknown_toml or unknown_overrides:
        unknown = min(unknown_toml | unknown_overrides)
        raise ValueError(f"unknown scanner configuration key: {unknown}")

    for name in names:
        environment_name = f"{_PREFIX}{name.upper()}"
        if environment_name in environ:
            values[name] = environ[environment_name]
    values.update({name: value for name, value in overrides.items() if value is not None})
    return ScannerConfig(
        concurrency=int(_coerce("concurrency", values.get("concurrency", 4))),
        active=bool(_coerce("active", values.get("active", False))),
        allow_private_targets=bool(
            _coerce("allow_private_targets", values.get("allow_private_targets", False))
        ),
        max_body_bytes=int(_coerce("max_body_bytes", values.get("max_body_bytes", 1_048_576))),
        max_redirects=int(_coerce("max_redirects", values.get("max_redirects", 5))),
        connect_timeout_seconds=float(
            _coerce("connect_timeout_seconds", values.get("connect_timeout_seconds", 10.0))
        ),
        read_timeout_seconds=float(
            _coerce("read_timeout_seconds", values.get("read_timeout_seconds", 20.0))
        ),
    )

#!/usr/bin/env python3
"""Run a SecMan scan with a JSON secret fetched through the AWS CLI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ALLOWED_KEYS = frozenset(
    {
        "SECMAN_URL",
        "SECMAN_SCANNER_ID",
        "SECMAN_SECURITY_SCANNER_ID",
        "SECMAN_VISUAL_SCANNER_ID",
        "SECMAN_TOKEN",
        "SECMAN_USERNAME",
        "SECMAN_PASSWORD",
        "SECMAN_VISION_API_KEY",
        "SECMAN_VISION_MODEL",
        "SECMAN_VISION_BASE_URL",
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch one AWS Secrets Manager JSON object and run a SecMan scan."
    )
    parser.add_argument("--secret-id", required=True, help="AWS secret name or ARN")
    parser.add_argument("--region", help="AWS region (otherwise use the normal AWS chain)")
    parser.add_argument("scan_args", nargs=argparse.REMAINDER)
    return parser


def _load_secret(secret_id: str, region: str | None) -> dict[str, str]:
    command = [
        "aws",
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        secret_id,
        "--query",
        "SecretString",
        "--output",
        "text",
    ]
    if region:
        command.extend(("--region", region))
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("AWS Secrets Manager lookup failed")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("AWS secret must contain one JSON object") from error
    if not isinstance(document, dict):
        raise RuntimeError("AWS secret must contain one JSON object")
    unknown = set(document) - ALLOWED_KEYS
    if unknown:
        raise RuntimeError(f"AWS secret contains unsupported key: {min(unknown)}")
    values: dict[str, str] = {}
    for key, value in document.items():
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"AWS secret key {key} must contain a non-empty string")
        values[key] = value
    return values


def main() -> int:
    args = _parser().parse_args()
    scan_args = list(args.scan_args)
    if scan_args[:1] == ["--"]:
        scan_args = scan_args[1:]
    if not scan_args:
        print("error: provide a target or scan options after --", file=sys.stderr)
        return 2
    if shutil.which("aws") is None:
        print("error: AWS CLI was not found", file=sys.stderr)
        return 2
    try:
        secrets = _load_secret(args.secret_id, args.region)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment.update(secrets)
    repository = Path(__file__).resolve().parents[1]
    command = [
        "uv",
        "run",
        "--locked",
        "secman-web-check",
        "scan",
        *scan_args,
        "--push-to-secman",
    ]
    os.chdir(repository)
    os.execvpe(command[0], command, environment)
    return 2  # pragma: no cover - exec replaces this process


if __name__ == "__main__":
    raise SystemExit(main())

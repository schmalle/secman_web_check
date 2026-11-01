"""Hash-pinned, operator-reviewed external engine assets and macOS confinement."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ExternalProfile:
    document_json: str
    digest: str

    def entry(self, name: str) -> dict[str, Any]:
        value = json.loads(self.document_json)["engines"].get(name)
        if not isinstance(value, dict):
            raise TypeError("external engine is not in the reviewed profile")
        return value

    def provenance(self) -> dict[str, Any]:
        return {
            "sha256": self.digest,
            "engines": {
                name: {
                    "version": entry["version"],
                    "binarySha256": entry["sha256"],
                    "assets": sorted(item["sha256"] for item in entry["assets"]),
                }
                for name, entry in json.loads(self.document_json)["engines"].items()
            },
        }


def load_external_profile(path: Path, expected_sha256: str) -> ExternalProfile:
    if path.stat().st_size > 65536:
        raise ValueError("external profile exceeds 64 KiB")
    raw = path.read_bytes()
    if (
        not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        or sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError("external profile checksum mismatch")
    doc = json.loads(raw)
    if (
        not isinstance(doc, dict)
        or doc.get("version") != 1
        or not isinstance(doc.get("engines"), dict)
    ):
        raise ValueError("invalid external profile")
    if not doc["engines"] or set(doc["engines"]) - {"nuclei", "nikto"}:
        raise ValueError("unsupported external engine")
    for entry in doc["engines"].values():
        if not isinstance(entry, dict) or entry.get("reviewedReadOnly") is not True:
            raise ValueError("external profile requires reviewed read-only assets")
        if not isinstance(entry.get("version"), str) or not entry["version"]:
            raise ValueError("external profile requires a tested version")
        if not isinstance(entry.get("assets"), list) or not 1 <= len(entry["assets"]) <= 200:
            raise ValueError("external profile requires 1–200 pinned assets")
        for asset in [entry, *entry["assets"]]:
            asset_path = Path(asset.get("path", ""))
            if not asset_path.is_absolute() or not re.fullmatch(
                r"[a-f0-9]{64}", asset.get("sha256", "")
            ):
                raise ValueError("external assets require absolute paths and SHA-256")
    return ExternalProfile(raw.decode(), expected_sha256)


def verified_copy(asset: dict[str, Any], destination: Path) -> Path:
    source = Path(asset["path"])
    if source.stat().st_size > 256_000_000:
        raise ValueError("external asset exceeds size limit")
    data = source.read_bytes()
    if sha256(data).hexdigest() != asset["sha256"]:
        raise ValueError("external asset checksum mismatch")
    destination.write_bytes(data)
    destination.chmod(0o700)
    return destination


def confined_run(
    command: list[str],
    output: Path,
    timeout: float,
    proxy_port: int,
    readable_assets: tuple[Path, ...],
) -> None:
    """Child can only reach the scope proxy; unsupported containment is an error."""
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists():
        raise RuntimeError("external scanners require enforced macOS sandbox containment")

    def quote(value: Path) -> str:
        return json.dumps(str(value))

    read_rules = " ".join(f"(literal {quote(path)})" for path in readable_assets)
    profile = (
        "(version 1)(allow default)(deny network*)"
        f'(allow network-outbound (remote ip "localhost:{proxy_port}"))'
        '(deny file-read-data (subpath "/Users")(subpath "/private/var/root"))'
        f"(allow file-read-data (subpath {quote(output.parent)}) {read_rules})"
        "(deny file-write*)"
        f'(allow file-write* (subpath {quote(output.parent)})(literal "/dev/null"))'
    )

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "secman_web_check.external_worker",
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            *command,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=output.parent,
        env={"PATH": "/usr/bin:/bin", "HOME": str(output.parent), "TMPDIR": str(output.parent)},
        start_new_session=False,
    )
    try:
        code = process.wait(timeout=timeout)
    except BaseException:
        process.kill()
        process.wait(timeout=5)
        raise
    if code not in {0, 1} or not output.exists() or output.stat().st_size > 2_000_000:
        raise RuntimeError(
            f"external scanner failed confinement or output limits (exit {code}; output exists={output.exists()})"
        )

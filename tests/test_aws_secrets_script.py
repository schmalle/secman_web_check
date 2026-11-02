from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_aws_wrapper_exports_allowlisted_secret_without_echoing_values(tmp_path: Path) -> None:
    calls = tmp_path / "calls.txt"
    _executable(
        tmp_path / "aws",
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" > "$CALLS"\n'
        'printf \'%s\\n\' \'{"SECMAN_URL":"https://secman.example",'
        '"SECMAN_TOKEN":"hidden-token","SECMAN_SCANNER_ID":"42"}\'\n',
    )
    _executable(
        tmp_path / "uv",
        '#!/usr/bin/env bash\nprintf \'uv %s token=%s\\n\' "$*" "$SECMAN_TOKEN" >> "$CALLS"\n',
    )
    script = Path(__file__).parents[1] / "scripts" / "scan-with-aws-secrets.py"
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "CALLS": str(calls),
    }

    result = subprocess.run(
        [
            str(script),
            "--secret-id",
            "prod/secman/web-check",
            "--",
            "example.com",
            "--fail-on",
            "none",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    recorded = calls.read_text(encoding="utf-8")
    assert "get-secret-value --secret-id prod/secman/web-check" in recorded
    assert "secman-web-check scan example.com --fail-on none --push-to-secman" in recorded
    assert "hidden-token" in recorded
    assert "hidden-token" not in result.stdout + result.stderr

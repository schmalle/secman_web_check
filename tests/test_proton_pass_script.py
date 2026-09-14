from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_proton_pass_wrapper_resolves_env_and_enables_secman_upload(tmp_path: Path) -> None:
    calls = tmp_path / "calls.txt"
    env_file = tmp_path / "scanner.env"
    env_file.write_text("SECMAN_TOKEN=pass://Test/SecMan/token\n", encoding="utf-8")
    _executable(
        tmp_path / "pass-cli",
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" > "$CALLS"\n'
        "while [[ $# -gt 0 && $1 != -- ]]; do shift; done\n"
        "shift\n"
        'exec "$@"\n',
    )
    _executable(
        tmp_path / "uv",
        '#!/usr/bin/env bash\nprintf \'uv %s\\n\' "$*" >> "$CALLS"\n',
    )
    script = Path(__file__).parents[1] / "scripts" / "scan-with-proton-pass.sh"
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "CALLS": str(calls),
    }

    result = subprocess.run(
        [str(script), "--env-file", str(env_file), "example.com", "--fail-on", "none"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    recorded = calls.read_text(encoding="utf-8")
    assert f"run --env-file {env_file} --" in recorded
    assert "secman-web-check scan example.com --fail-on none --push-to-secman" in recorded
    assert "pass://Test/SecMan/token" not in recorded

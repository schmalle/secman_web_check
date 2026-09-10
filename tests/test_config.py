from pathlib import Path

from secman_web_check.config import load_config


def test_cli_values_override_environment_and_toml(tmp_path: Path) -> None:
    path = tmp_path / "scanner.toml"
    path.write_text("[scan]\nconcurrency = 4\n", encoding="utf-8")

    config = load_config(path, {"SECMAN_WEB_CHECK_CONCURRENCY": "6"}, concurrency=8)

    assert config.concurrency == 8


def test_environment_values_override_toml_values(tmp_path: Path) -> None:
    path = tmp_path / "scanner.toml"
    path.write_text("[scan]\nactive = false\n", encoding="utf-8")

    config = load_config(path, {"SECMAN_WEB_CHECK_ACTIVE": "true"})

    assert config.active is True

#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
uv sync --locked --all-groups
uv run --locked python -m playwright install chromium
uv run --locked secman-web-check --help

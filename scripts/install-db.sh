#!/usr/bin/env bash
set -euo pipefail

: "${SECMAN_WEB_CHECK_DB_HOST:?SECMAN_WEB_CHECK_DB_HOST is required}"
: "${SECMAN_WEB_CHECK_DB_USER:?SECMAN_WEB_CHECK_DB_USER is required}"
: "${SECMAN_WEB_CHECK_DB_PASSWORD:?SECMAN_WEB_CHECK_DB_PASSWORD is required}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
exec uv run --locked secman-web-check db install

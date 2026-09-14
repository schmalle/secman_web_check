#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--env-file FILE] TARGET_OR_SCAN_OPTIONS..."
  echo "Runs a scan with --push-to-secman after pass-cli resolves the env file."
}

if [[ ${1:-} == --help ]]; then
  usage
  exit 0
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${SECMAN_WEB_CHECK_PASS_ENV_FILE:-$repo_dir/.env}"
if [[ ${1:-} == --env-file ]]; then
  if [[ $# -lt 2 ]]; then
    usage >&2
    exit 2
  fi
  env_file=$2
  shift 2
fi
if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi
if [[ ! -r $env_file ]]; then
  echo "error: Proton Pass env file is not readable: $env_file" >&2
  exit 2
fi

pass_cli="${SECMAN_PASS_CLI:-pass-cli}"
if ! command -v "$pass_cli" >/dev/null 2>&1; then
  echo "error: Proton Pass CLI not found: $pass_cli" >&2
  echo "Install pass-cli or set SECMAN_PASS_CLI to its path." >&2
  exit 2
fi

cd "$repo_dir"
exec "$pass_cli" run --env-file "$env_file" -- \
  uv run --locked secman-web-check scan "$@" --push-to-secman

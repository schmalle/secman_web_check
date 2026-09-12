#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  echo "usage: $0 TARGET [-- SCAN_OPTIONS...]"
  exit 0
fi
if [[ $# -lt 1 ]]; then
  echo "usage: $0 TARGET [-- SCAN_OPTIONS...]" >&2
  exit 2
fi
target=$1
shift
if [[ ${1:-} == -- ]]; then
  shift
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
exec uv run --locked secman-web-check scan "$target" "$@"

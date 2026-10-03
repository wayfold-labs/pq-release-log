#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ ! -x .venv/bin/python ]]; then
  echo "FAIL: .venv is missing; install cli/requirements.txt with --require-hashes" >&2
  exit 1
fi

forge build >/dev/null 2>&1
exec .venv/bin/python test/killtest.py

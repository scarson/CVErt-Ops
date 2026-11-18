#!/usr/bin/env bash
# Thin Unix wrapper: find a Python 3 interpreter and exec bootstrap.py.
# All real logic lives in bootstrap.py so there is one source of truth.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_PY="$HERE/bootstrap.py"

for py in python3 python; do
  if command -v "$py" >/dev/null 2>&1; then
    exec "$py" "$BOOTSTRAP_PY" "$@"
  fi
done

echo "ERROR: No Python 3 interpreter found on PATH." >&2
echo "Install Python 3.9 or newer from https://python.org and retry." >&2
exit 5

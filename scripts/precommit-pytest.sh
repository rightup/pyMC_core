#!/usr/bin/env bash
set -euo pipefail

# Prefer the currently activated venv, then repo-local .venv, then python3/python.
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
  PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
elif [ -x ".venv/bin/python" ]; then
  PYTHON_BIN=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "No Python interpreter found for pytest hook." >&2
  exit 1
fi

exec "${PYTHON_BIN}" -m pytest -q

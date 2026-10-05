#!/bin/sh
# One-shot verification entrypoint: unit tests, build (bytecode) check and
# end-to-end smoke submissions against the running service.
set -eu

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"

echo "==> unit tests"
"$PYTHON" -m pytest -q

echo "==> build check (bytecode compilation)"
"$PYTHON" -m compileall -q app tests scripts

echo "==> smoke submissions against ${BASE_URL}"
"$PYTHON" scripts/smoke.py

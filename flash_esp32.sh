#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PY_BIN="python3"
if [ -f "venv/bin/python3" ]; then
    PY_BIN="venv/bin/python3"
fi

"$PY_BIN" "scripts/flash_esp32.py"

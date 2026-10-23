#!/bin/sh
# Explicitly invoked, optional inventory only. Never installs or logs in.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. No discovery request sent." >&2
  exit 127
fi
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/discover.py" "$@"

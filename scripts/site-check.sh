#!/bin/sh
set -eu
if ! command -v python3 >/dev/null 2>&1; then
  echo "Swarm Site Check needs Python 3 (3.9 or later). No requests were sent. Ask your host or developer to provide Python 3; no pip packages are needed." >&2
  exit 127
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  echo "Swarm Site Check needs Python 3.9 or later. No requests were sent." >&2
  exit 2
fi
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/site_check.py" "$@"

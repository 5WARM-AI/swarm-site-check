#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname -- "$SCRIPT_DIR")
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.9 or later is required. No requests were sent; no pip packages are needed." >&2
  exit 127
fi
cd "$ROOT"
case "${1:-}" in
  ""|--offline) ;;
  *) echo "Usage: scripts/selftest.sh [--offline]" >&2; exit 2 ;;
esac
python3 -m unittest -v
if [ "${1:-}" = "--offline" ]; then
  echo "Offline self-test passed: synthetic parsers, transport mocks, consent and report review/render checks. No network requests."
  exit 0
fi
echo "Live demonstration scope: https://example.com/"
echo "This sends the ordinary passive check requests to example.com, public DNS and OSV."
echo "Type 'check example.com' to authorize this public demonstration (anything else stops):"
IFS= read -r consent || exit 2
if [ "$consent" != "check example.com" ]; then
  echo "Stopped before network requests."
  exit 2
fi
mkdir -p .work
RUN_DIR=$(mktemp -d "$ROOT/.work/selftest.XXXXXX")
sh "$SCRIPT_DIR/site-check.sh" scope example.com --out "$RUN_DIR/scope.json"
DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$RUN_DIR/scope.json")
# Explicit demonstration authorization above is confined to the fixed example.com scope.
sh "$SCRIPT_DIR/site-check.sh" run --scope "$RUN_DIR/scope.json" --confirmed-scope "$DIGEST" --ownership "these are sites I own or run" --output "$RUN_DIR/run"
echo "Self-test collection complete. Evidence: $RUN_DIR/run/raw/evidence.json"
echo "Independent Claude review and report generation are exercised by /site-check."

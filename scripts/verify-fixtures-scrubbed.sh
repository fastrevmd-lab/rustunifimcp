#!/bin/sh
# Verify that fixture files contain no sensitive data.
#
# Usage: verify-fixtures-scrubbed.sh <fixture-dir>
#
# Exit codes:
#   0  all fixtures clean
#   1  sensitive data found or fixture directory empty
#   2  usage error

set -eu

if [ $# -lt 1 ]; then
    printf 'Usage: %s <fixture-dir>\n' "$0" >&2
    exit 2
fi

FIXTURE_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$SCRIPT_DIR/verify-fixtures-scrubbed.py" "$FIXTURE_DIR"

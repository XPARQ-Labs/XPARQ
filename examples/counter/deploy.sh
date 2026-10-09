#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == --help || "${1:-}" == -h || $# == 0 ]]; then
    printf 'Usage: %s NONCE [additional wallet options]\n' "$0"
    printf 'Deploy a persistent XPVM counter starting at zero.\n'
    exit 0
fi
exec "$SCRIPT_DIR/../deploy/deploy.sh" "$SCRIPT_DIR/counter.xpvm" "$@"

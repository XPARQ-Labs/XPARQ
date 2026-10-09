#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == --help || "${1:-}" == -h || $# == 0 ]]; then
    printf 'Usage: %s NONCE [additional wallet options]\n' "$0"
    printf 'Deploy an example XPVM program that returns 7.\n'
    exit 0
fi

CODE_FILE="$(mktemp "${TMPDIR:-/tmp}/xparq-return7.XXXXXX")"
trap 'rm -f -- "$CODE_FILE"' EXIT
# XPVM v1: stack limit 1, zero memory pages, entry 0; PUSH_I64 7; RETURN.
printf '\x58\x50\x56\x4d\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x07\x00\x00\x00\x00\x00\x00\x00\x03' > "$CODE_FILE"
"$SCRIPT_DIR/deploy.sh" "$CODE_FILE" "$@"

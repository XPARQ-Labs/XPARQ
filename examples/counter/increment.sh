#!/usr/bin/env bash
set -euo pipefail
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ "${1:-}" == --help || "${1:-}" == -h || $# == 0 ]]; then
    printf 'Usage: %s PROGRAM_ID [additional wallet options]\n' "$0"
    printf 'Submit one counter increment. Wait for confirmation before the next call.\n'
    exit 0
fi
PROGRAM_ID="$1"
shift
[[ "$PROGRAM_ID" =~ ^[[:xdigit:]]{64}$ ]] || { printf 'Program ID must be 64 hexadecimal characters.\n' >&2; exit 1; }
WALLET_BIN="${WALLET_BIN:-$REPO_DIR/target/release/wallet}"
WALLET_FILE="${WALLET_FILE:-$REPO_DIR/wallet.json}"
RPC_ADDR="${RPC_ADDR:-127.0.0.1:6666}"
[[ -x "$WALLET_BIN" ]] || { printf 'Wallet binary not found. Run ./build.sh first.\n' >&2; exit 1; }
[[ -f "$WALLET_FILE" ]] || { printf 'Wallet file not found: %s\n' "$WALLET_FILE" >&2; exit 1; }
exec "$WALLET_BIN" program-call --program-id "$PROGRAM_ID" --wallet "$WALLET_FILE" --rpc "$RPC_ADDR" "$@"

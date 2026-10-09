#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    printf 'Usage: %s CODE.xpvm NONCE [additional wallet options]\n' "$0"
    printf 'Environment: WALLET_BIN, WALLET_FILE, RPC_ADDR\n'
    exit 0
fi
if (( $# < 2 )); then
    printf 'Usage: %s CODE.xpvm NONCE [additional wallet options]\n' "$0" >&2
    exit 1
fi
CODE_FILE="$1"
NONCE="$2"
shift 2
WALLET_BIN="${WALLET_BIN:-$REPO_DIR/target/release/wallet}"
WALLET_FILE="${WALLET_FILE:-$REPO_DIR/wallet.json}"
RPC_ADDR="${RPC_ADDR:-127.0.0.1:6666}"

[[ -f "$CODE_FILE" ]] || { printf 'Bytecode file not found: %s\n' "$CODE_FILE" >&2; exit 1; }
[[ "$NONCE" =~ ^[0-9]+$ ]] || { printf 'Nonce must be a nonnegative integer.\n' >&2; exit 1; }
[[ -x "$WALLET_BIN" ]] || { printf 'Wallet binary not found. Run ./build.sh first.\n' >&2; exit 1; }
[[ -f "$WALLET_FILE" ]] || { printf 'Wallet file not found: %s\n' "$WALLET_FILE" >&2; exit 1; }

exec "$WALLET_BIN" program-deploy --code "$CODE_FILE" --nonce "$NONCE" \
    --wallet "$WALLET_FILE" --rpc "$RPC_ADDR" "$@"

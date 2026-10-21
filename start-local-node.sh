#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

if [[ $# -ne 1 || ! "$1" =~ ^[a-j]$ ]]; then
    printf 'Usage: %s {a|b|c|d|e|f|g|h|i|j}\n' "$0" >&2
    printf 'Configure addresses with RPC_A..RPC_J, P2P_A..P2P_J, and MINER_A..MINER_J environment variables.\n' >&2
    exit 2
fi

NODE="${NODE_BIN:-$REPO_DIR/target/release/node}"
MINER_A="${MINER_A:-23e2401328a76c693ead39ea69129dd225a25a36af3d71495b6ef0d08e263715}"
MINER_B="${MINER_B:-6023650750e567f9af1aa6b7990d9d4cf1780779298c9d6e9eeee404ecac8c3d}"

NODE_INDEX=$(( $(printf '%d' "'${1}") - 96 ))
NODE_LETTER="${1^^}"
RPC_VAR="RPC_${NODE_LETTER}"
P2P_VAR="P2P_${NODE_LETTER}"
MINER_VAR="MINER_${NODE_LETTER}"
RPC_PORT=$((26665 + NODE_INDEX))
P2P_PORT=$((26776 + NODE_INDEX))
RPC_ADDRESS="${!RPC_VAR:-127.0.0.1:$RPC_PORT}"
P2P_ADDRESS="${!P2P_VAR:-127.0.0.1:$P2P_PORT}"
MINER="${!MINER_VAR:-${MINER_A:-${MINER_B:-}}}"

if [[ ! -x "$NODE" ]]; then
    printf 'Node binary not found or not executable: %s\nBuild it with ./build.sh\n' "$NODE" >&2
    exit 1
fi

if [[ -z "$MINER" ]]; then
    printf 'Set %s to this node\x27s miner ProgramId.\n' "$MINER_VAR" >&2
    exit 1
fi

ARGS=(run --data "./data/local-$1" --p2p "$P2P_ADDRESS" --rpc "$RPC_ADDRESS" --miner "$MINER")
if [[ "$1" != "a" ]]; then
    PREVIOUS_LETTER="$(printf \\$(printf '%03o' "$(( $(printf '%d' "'${1}") - 1 ))"))"
    PREVIOUS_VAR="P2P_${PREVIOUS_LETTER^^}"
    PREVIOUS_PORT=$((P2P_PORT - 1))
    PREVIOUS_ADDRESS="${!PREVIOUS_VAR:-127.0.0.1:$PREVIOUS_PORT}"
    ARGS+=(--peer "$PREVIOUS_ADDRESS")
fi

exec "$NODE" "${ARGS[@]}"

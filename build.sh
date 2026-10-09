#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root, even when invoked from another directory.
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$REPO_DIR"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    printf 'Usage: %s [additional cargo build options]\n' "$0"
    printf 'Build node and wallet in release mode. Example: %s --locked\n' "$0"
    exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
    printf 'Error: cargo was not found. Install Rust 1.90 or newer, then run this script again.\n' >&2
    exit 1
fi

if ! command -v cc >/dev/null 2>&1; then
    printf 'Error: the C compiler/linker cc was not found.\n' >&2
    printf 'On Debian/Ubuntu, run:\n  sudo apt update\n  sudo apt install build-essential pkg-config\n' >&2
    printf 'Then run build.sh again.\n' >&2
    exit 1
fi

printf 'Building node and wallet (release)...\n'
cargo build --release --locked -p node -p wallet "$@"
printf 'Node and wallet built successfully.\n'

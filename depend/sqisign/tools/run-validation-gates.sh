#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SQISIGN_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
XPARQ_DIR=$(CDPATH= cd -- "$SQISIGN_DIR/../.." && pwd)

cd "$XPARQ_DIR"

echo "[1/5] default XPARQ build"
cargo check --workspace --offline

echo "[2/5] isolated SQIsign dependency build"
cargo check --offline --manifest-path "$SQISIGN_DIR/sqisign-rs/Cargo.toml"

echo "[3/5] dependency migration Level 1/3/5 tests"
cargo test --release --offline \
    --manifest-path "$SQISIGN_DIR/sqisign-rs/Cargo.toml" \
    --test dependency_upgrade_levels

echo "[4/5] pinned KAT checksums"
sh "$SCRIPT_DIR/validate-kat-checksums.sh"

echo "[5/5] Level 1/3/5 KAT validation"
cargo test --release --offline \
    --manifest-path "$SQISIGN_DIR/sqisign-verify/Cargo.toml" \
    --features kat-compat --test kat_validation

if [ -n "${SQISIGN_C_SOURCE:-}" ]; then
    echo "[optional] official C/Rust bidirectional cross-validation"
    sh "$SCRIPT_DIR/c-validate/run-cross-validation.sh"
else
    echo "[optional] C/Rust cross-validation skipped; set SQISIGN_C_SOURCE"
fi

echo "All locally available SQIsign validation gates passed"

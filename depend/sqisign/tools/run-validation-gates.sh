#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SQISIGN_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
XPARQ_DIR=$(CDPATH= cd -- "$SQISIGN_DIR/../.." && pwd)

cd "$XPARQ_DIR"

echo "[1/9] default XPARQ build"
cargo check --workspace --offline

echo "[2/9] isolated SQIsign candidate build"
cargo check --offline -p xparq --features sqisign-candidate

echo "[3/9] dependency migration Level 1/3/5 tests"
cargo test --release --offline \
    --manifest-path "$SQISIGN_DIR/sqisign-rs/Cargo.toml" \
    --test dependency_upgrade_levels

echo "[4/9] pinned KAT checksums"
sh "$SCRIPT_DIR/validate-kat-checksums.sh"

echo "[5/9] Level 1/3/5 KAT validation"
cargo test --release --offline \
    --manifest-path "$SQISIGN_DIR/sqisign-verify/Cargo.toml" \
    --features kat-compat --test kat_validation

echo "[6/9] Level 5 dual-authorization negative tests"
cargo test --release --offline -p xparq --features sqisign-candidate \
    --test sqisign_candidate -- --ignored

echo "[7/9] devnet SQIsign backend tests"
cargo test --offline -p xparq --no-default-features --features devnet \
    crypto::keygen::tests

echo "[8/9] fuzz harness compilation"
cargo check --offline --manifest-path core/fuzz/Cargo.toml
cargo check --offline --manifest-path core/fuzz/Cargo.toml \
    --features sqisign-parser --bin sqisign_parser

echo "[9/9] benchmark compilation"
cargo check --offline -p xparq --features sqisign-candidate \
    --bench sqisign_candidate
cargo check --offline -p xparq --no-default-features --features devnet \
    --bench sqisign_verifier

if [ -n "${SQISIGN_C_SOURCE:-}" ]; then
    echo "[optional] official C/Rust bidirectional cross-validation"
    sh "$SCRIPT_DIR/c-validate/run-cross-validation.sh"
else
    echo "[optional] C/Rust cross-validation skipped; set SQISIGN_C_SOURCE"
fi

echo "All locally available SQIsign validation gates passed"

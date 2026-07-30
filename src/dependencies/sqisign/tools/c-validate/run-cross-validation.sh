#!/bin/sh
set -eu

EXPECTED_COMMIT=dd133d7aca576c361a270c8e6434832535b42ecc
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SQISIGN_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PAQUS_DIR=$(CDPATH= cd -- "$SQISIGN_DIR/../../.." && pwd)
C_SOURCE=${SQISIGN_C_SOURCE:?set SQISIGN_C_SOURCE to the-sqisign checkout}
CMAKE_BIN=${CMAKE_BIN:-cmake}
BUILD_DIR=${SQISIGN_C_BUILD_DIR:-"$C_SOURCE/build-paqus-cross"}
VECTOR_DIR=${SQISIGN_C_VECTOR_DIR:-"$BUILD_DIR/paqus-vectors"}

ACTUAL_COMMIT=$(git -C "$C_SOURCE" rev-parse HEAD)
if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "unexpected C reference commit: $ACTUAL_COMMIT" >&2
    exit 1
fi

"$CMAKE_BIN" -S "$C_SOURCE" -B "$BUILD_DIR" \
    -DGMP_LIBRARY=MINI \
    -DSQISIGN_BUILD_TYPE=ref \
    -DCMAKE_BUILD_TYPE=Release
"$CMAKE_BIN" --build "$BUILD_DIR" --parallel

cargo test --release --offline \
    --manifest-path "$SQISIGN_DIR/sqisign-verify/Cargo.toml" \
    --features kat-compat --test kat_validation

cargo run --release --offline \
    --manifest-path "$SQISIGN_DIR/sqisign-rs/Cargo.toml" \
    --example c_interop_vectors -- "$VECTOR_DIR"

compile_verifier() {
    level=$1
    cc -O2 -std=c11 \
        -DSQISIGN_VARIANT="$level" \
        -DSQISIGN_BUILD_TYPE_REF \
        -I"$C_SOURCE/include" \
        -I"$C_SOURCE/src/nistapi/$level" \
        "$SCRIPT_DIR/verify_nistapi.c" \
        -o "$BUILD_DIR/paqus-c-verify-$level" \
        "$BUILD_DIR/src/libsqisign_${level}_nistapi.a" \
        "$BUILD_DIR/src/libsqisign_${level}.a" \
        "$BUILD_DIR/src/signature/ref/$level/libsqisign_signature_${level}.a" \
        "$BUILD_DIR/src/verification/ref/$level/libsqisign_verification_${level}.a" \
        "$BUILD_DIR/src/id2iso/ref/$level/libsqisign_id2iso_${level}.a" \
        "$BUILD_DIR/src/quaternion/ref/generic/libsqisign_quaternion_generic.a" \
        -lm \
        "$BUILD_DIR/src/hd/ref/$level/libsqisign_hd_${level}.a" \
        "$BUILD_DIR/src/ec/ref/$level/libsqisign_ec_${level}.a" \
        "$BUILD_DIR/src/gf/ref/$level/libsqisign_gf_${level}.a" \
        "$BUILD_DIR/src/mp/ref/generic/libsqisign_mp_generic.a" \
        "$BUILD_DIR/src/precomp/ref/$level/libsqisign_precomp_${level}.a" \
        "$BUILD_DIR/libGMP.a" \
        "$BUILD_DIR/src/common/generic/libsqisign_common_sys.a"
}

for level in lvl1 lvl3 lvl5; do
    compile_verifier "$level"
    "$BUILD_DIR/paqus-c-verify-$level" "$VECTOR_DIR/$level-valid.bin" valid
    "$BUILD_DIR/paqus-c-verify-$level" "$VECTOR_DIR/$level-invalid.bin" invalid
done

cargo check --release --offline --features sqisign-candidate \
    --manifest-path "$PAQUS_DIR/Cargo.toml"

echo "SQIsign C/Rust cross-validation passed"

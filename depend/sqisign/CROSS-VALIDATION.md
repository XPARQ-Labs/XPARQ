# XPARQ SQIsign C/Rust cross-validation

## Scope

This test compares `xparq-sqisign` against the official SQIsign C reference
implementation. The C implementation is test-only and is not linked into the
XPARQ library or consensus binary.

Official C source:

- Repository: `https://github.com/SQISign/the-sqisign`
- Commit: `dd133d7aca576c361a270c8e6434832535b42ecc`
- Build: reference backend, bundled mini-GMP, Release profile

## Results

Run date: 2026-07-29

- Official C-generated KAT signatures to Rust verifier:
  - Level 1: all 100 vectors passed
  - Level 3: all 100 vectors passed
  - Level 5: all 100 vectors passed
  - Standard, expanded, and compressed Rust formats passed
- Rust-generated signatures to official C verifier:
  - Level 1: accepted
  - Level 3: accepted
  - Level 5: accepted
- Rust-generated signatures with a flipped bit to official C verifier:
  - Level 1: rejected
  - Level 3: rejected
  - Level 5: rejected

This proves signature-wire interoperability in both directions. It does not
claim byte-identical randomized key generation or signing because the Rust and
C implementations consume different RNG interfaces and streams.

## Reproduction

Clone the official C source and pin it:

```sh
git clone https://github.com/SQISign/the-sqisign.git /tmp/the-sqisign
git -C /tmp/the-sqisign checkout --detach dd133d7aca576c361a270c8e6434832535b42ecc
```

Run:

```sh
SQISIGN_C_SOURCE=/tmp/the-sqisign \
depend/sqisign/tools/c-validate/run-cross-validation.sh
```

`cmake`, a C11 compiler, Cargo, and the Rust toolchain are required. Set
`CMAKE_BIN` if CMake is installed outside `PATH`.

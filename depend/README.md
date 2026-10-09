# XPARQ Dependency Boundary

This directory contains the Rust packages vendored by XPARQ. Dependency paths
and crates.io overrides are declared centrally in the repository-root
`Cargo.toml`.

The packages are kept outside the main Cargo workspace and retain their
original package names. In particular, procedural macros and trait crates such
as `serde`, `borsh`, and their derive packages cannot be flattened into one
Cargo package without changing macro resolution and public trait identities.

First-party workspace crates should add shared dependencies through
`[workspace.dependencies]` in the root manifest instead of declaring new
versions independently.

`depend/Cargo.toml` lists concrete excluded package paths so Cargo tools can
inspect each vendored manifest as an independent package. When adding a vendor
crate, add its relative directory to that exclusion list.

`depend/rustfmt.toml` preserves upstream source formatting. `cargo fmt --all`
may visit local path dependencies, but formatting checks apply normally to the
first-party workspace crates without rewriting vendored cryptographic source.

SLH-DSA is pinned to RustCrypto `slh-dsa 0.2.0-rc.5` in `slhdsa/slh-dsa`,
with zeroize enabled. It shares the existing `mldsa/shake` and `keccak` implementations. SHA2/HMAC
are vendored in `slhdsa/` and enabled only by the explicit benchmark feature;
`utils/block-buffer-0.12` serves digest 0.11 without replacing block-buffer 0.10
used by legacy dependencies. See [signature policy](../docs/SIGNATURE_SCHEMES.md)
for enabled parameters, seed derivation and upstream audit status.

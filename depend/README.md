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

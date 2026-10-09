# Build and dependency tooling

## Reproducible dependency selection

`rust-toolchain.toml` selects Rust 1.99.0 with rustfmt and Clippy. Use rustup to
install the pinned toolchain. `Cargo.toml` still declares Rust 1.90 as the
workspace minimum; this change does not certify the dependency graph on that
older compiler. The development and validation toolchain is the pinned version.

Commit `Cargo.lock` for this node/wallet workspace. `build.sh` passes `--locked`
so builds fail if the lockfile needs an update. This locks dependency selection;
it does not guarantee byte-identical binaries across operating systems, linker
versions, environment variables, or local vendored-source changes.

`.cargo/config.toml` adds these aliases:

```bash
cargo check-all
cargo fmt-check
cargo lint
```

The configuration preserves default CPU and linker selection. Choose a target
explicitly when cross-compiling. Machine-specific performance flags can be
supplied locally, but distributed binaries must match their intended CPUs.
`rustfmt.toml` configures edition 2024 and a maximum line width of 100. Vendored
crates may have their own formatting configuration.

## Dependency policy

Install cargo-deny and run checks from the repository root:

```bash
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --locked check
cargo deny --locked --no-default-features --features testnet check
cargo deny --locked --no-default-features --features devnet check
cargo deny --locked --no-default-features --features node/litep2p-devnet check
```

These checks need registry metadata and an up-to-date RustSec advisory database.
Network features are checked individually rather than enabling mainnet,
testnet, and devnet together. The default graph is mainnet. The optional litep2p devnet graph is checked
separately.

`deny.toml` reports duplicate versions as warnings, rejects wildcard dependency
requirements and unapproved registries/Git sources, and lists accepted license
identifiers. Local inter-crate path dependencies declare version `0.1.0`; update these
requirements alongside the workspace version when releasing. The license
allowlist includes ISC, used by the optional litep2p dependency graph.
It does not suppress security advisories. An accepted license ID
is an input to dependency policy, not a substitute for preserving required
license notices in distributed artifacts.

Vendored/path dependencies are local source trees. Advisory checks cannot prove
that a local fork is equivalent to its upstream version or contains a fix.
Changes to vendored cryptographic code still require source review and tests.

Configuration follows the [cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/checks/cfg.html).

## Protocol configuration

Canonical consensus constants remain in Rust source and the existing chain
specification. This change adds no runtime TOML override for PoW, emission,
block limits, or network identity. Operational node settings continue to use
the existing CLI. Add cross-compilation, nextest, or release-tool configurations
when those workflows are implemented and verified.

## Verification

On 2026-10-04, cargo-deny 0.20.2 passed advisories, bans, licenses, and sources
for mainnet, testnet, devnet, and optional litep2p-devnet. Duplicate dependency
versions remain visible as warnings. Workspace compilation, formatting, and
Clippy passed with existing warnings. `Cargo.lock` remained unchanged.
See [verification results](audit/tooling-verification.txt).

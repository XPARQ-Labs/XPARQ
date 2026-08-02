# Installation

## Requirements

You need:

* a current 64-bit Linux, macOS, or Windows environment;
* Rust `1.90` or newer;
* Cargo;
* Git;
* a C toolchain required by native dependencies.

Install Rust with [rustup](https://rustup.rs/), then verify it:

```bash
rustc --version
cargo --version
```

## Core crate

The `paqus` crate is published on crates.io. Node and wallet applications should
depend on the published crate version instead of a sibling checkout.

## Build

From the project root:

```bash
cargo build --release --bin paqus-node
cargo build --release --bin wallet-cli
```

The binaries are written to:

```text
target/release/paqus-node
target/release/wallet-cli
```

For development checks:

```bash
cargo check --bins
```

## Reclaim build space

Rust build artifacts can use several gigabytes. They are safe to recreate:

```bash
cargo clean
```

Cleaning does not remove source code, wallets, or blockchain databases.

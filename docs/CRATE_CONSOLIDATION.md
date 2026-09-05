# Crate Consolidation and Repository History

## Implemented workspace

The workspace has five packages. Protocol crates have been moved into modules
of the `kernel` package; `extension/bridge` is now `extension/src/bridge`.

| Package | Directory | Responsibility |
| --- | --- | --- |
| `kernel` | `xparq/` | Canonical protocol types, coin and asset primitives, transactions, blocks, consensus, ledger, genesis |
| `xparq-crypto` | `crypto/` | Cryptographic implementations and shared canonical encoding, hash, and scalar primitives |
| `xparq-extension` | `extension/` | Extension contracts, WASM execution, bounded host interface, bridge primitives |
| `xparq-node` | `runtime/` | Storage, networking, RPC, mempool, mining |
| `xparq-wallet` | `wallet/` | Wallet library, keys, transaction construction, user interface |

## Kernel and infrastructure boundaries

The kernel owns deterministic validity rules and in-memory ledger transitions.
The node owns persistence and networking. For example, consensus validates PoW;
the node runs the mining loop. Consensus does not depend on ledger storage.
Node and wallet consume the public `xparq` API.

Package dependencies point downwards:

```text
node / wallet -> kernel -> extension -> crypto
                   └----------------> crypto
```

The node also uses the wallet library in integration tests. Vendored sources
under `depend/` remain outside workspace membership.

The `kernel` package retains the library name `xparq`. Workspace consumers use
the `xparq` dependency alias with `package = "kernel"`, preserving Rust imports
and feature forwarding through `xparq/...`. Cargo package selection uses
`-p kernel`; the source directory remains `xparq/`.

Shared definitions have one owner to avoid circular dependencies:

- `crypto::primitives` owns canonical encoding, `CodecError`, domain hashing,
  `Height`, and `Nonce`. Crypto and extensions can use them without depending
  on the kernel.
- `extension::protocol` owns extension envelopes, state capabilities, limits,
  and commitments. WASM execution remains behind the extension host interface.
- `xparq::common` owns `Authority`, `Input`, and `Output`, and re-exports the
  lower-level definitions through the existing common API.

## Protocol module layout

```text
xparq/src/
├── common/
├── coin/
├── asset/
├── transaction/
├── blockchain/
├── consensus/
├── ledger/
├── genesis/
├── bin/print_genesis_hash.rs
└── lib.rs
```

The existing public paths `xparq::block`, `xparq::codec`, `xparq::crypto`,
`xparq::extension`, `xparq::consensus`, and `xparq::ledger` remain available.
`xparq::blockchain` also exposes the block and chain module directly.
The standalone `genesis/genesis.rs` draft was preserved at
`xparq/src/genesis/genesis.rs`; as before, it is not compiled into the protocol.

## Package maintenance and deployment

One repository does not require deploying every application together. Packages
can be maintained and checked individually; deployment distributes the affected
application binaries. The workspace currently shares package versions through
`workspace.package.version`, so separate deployment does not imply independent
package versioning or a separate repository for each crate.

| Change | Build and deployment scope |
| --- | --- |
| Wallet UI or key management | Build and distribute `wallet`; check node compatibility if transaction construction changes |
| Node RPC, P2P, or storage | Build and deploy `node`; check affected clients, peers, and database compatibility |
| Kernel, crypto, or extension library | Rebuild each application that needs the change and deploy its updated binary |
| Consensus rules, canonical encoding, or protocol hashes | Validate affected consumers and coordinate compatible node/wallet releases; determine whether state migration or a chain reset is required |

`kernel`, `xparq-crypto`, and `xparq-extension` are compiled into their consuming
applications. They are not standalone services or libraries that can be replaced
inside a running node. Editing their source does not update an existing binary.
The compiled extension host follows this rule; deploying a WASM program uses the
separate protocol described in [WASM_EXTENSIONS.md](WASM_EXTENSIONS.md).

For focused maintenance:

```bash
cargo check -p kernel --all-targets --locked
cargo test -p kernel --locked
cargo test -p xparq-crypto --locked
cargo test -p xparq-extension --locked
```

Build either application independently:

```bash
cargo build --release -p xparq-node --locked
cargo build --release -p xparq-wallet --locked
```

The resulting artifacts are `target/release/node` and `target/release/wallet`.
Cargo builds the selected application's required dependencies automatically;
building does not deploy or restart an application.

After changing a shared API, run the all-target workspace check to catch affected
consumers. Before releasing protocol changes, also run the relevant serialization,
genesis, ledger apply/rollback, reorg, and node/wallet integration tests below.
Package boundaries alone do not establish wire or consensus compatibility.

## Compatibility and validation

This is a package/module reorganization. Canonical Borsh encodings, hash
domains, identifiers, genesis identity, and consensus rules are preserved.
The move itself does not require a chain reset or database migration.
External consumers of removed crates must use the corresponding `xparq`
module; for example, `xparq_asset::AssetHash` becomes
`xparq::asset::AssetHash`. The existing node and wallet API paths are retained.

The genesis helper is now invoked with:

```bash
cargo run -p kernel --bin print_genesis_hash
```

Network features remain `mainnet` (default), `testnet`, and `devnet`;
`sqisign-blockchain-test` enables `devnet`. Select one network at a time,
using `--no-default-features` for an alternate network.

Validation commands:

```bash
cargo fmt -p kernel -p xparq-crypto -p xparq-extension -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo check --workspace --all-targets --no-default-features --features testnet --locked
cargo check --workspace --all-targets --no-default-features --features devnet --locked
```

`xparq/tests/consolidation_compatibility.rs` freezes mainnet genesis bytes,
genesis and chain-spec hashes, and asset/share identifiers captured before
the move. Existing serialization, apply/rollback, reorg, wallet, and node
integration tests remain part of the validation surface.

The consolidation was validated with all-target workspace checks for mainnet,
testnet, and devnet, formatting checks, and 117 passing workspace tests,
including four multi-node integration tests. Network tests require permission
to open localhost sockets. Public API documentation also builds; existing
vendored dependency warnings and the private `ChainSpecIdentity` documentation
link warning remain.

Two stale test setups were corrected during validation: the profile reveal
fixture now accounts for a consumed coin UTXO, and network tests build a fresh
chain with the current schema instead of loading the old database fixture.
The wallet gossip fixture funds its sender explicitly and includes canonical
history burn and relay fees. These changes affect tests only.

## New repository versus old history

The configured remote is `XPARQ-Labs/XPARQ-2`, and package metadata should use
that same URL. Pushing an existing branch to a new GitHub repository preserves
its commit ancestry by design. The old commits are history, not a reference to
the old remote.

The recommended policy is to keep that history and clean only active manifests,
documentation, examples, and generated API descriptions. Historical changelog
entries may continue to mention features or layouts that existed in old
releases, provided they are clearly historical.

If a repository with no previous ancestry is truly required, create a new root
commit (or filter the history) and force-push it. Both operations replace commit
IDs and disrupt existing clones, forks, links, and tags. They must be performed
only as a separately approved repository migration with a backup and an agreed
cutover plan; this cleanup does not rewrite Git history.

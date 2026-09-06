# XPARQ

XPARQ is a Rust proof-of-work blockchain with an XPQ UTXO ledger, native
Layer-1 assets, a TCP peer-to-peer node, HTTP RPC, and an
interactive wallet. Proof of work uses Argon2id, while canonical identifiers
and protocol hashes use domain-separated SHA3-256 where defined by their
respective modules.

The workspace targets Rust 1.90 and the Rust 2024 edition.

## Workspace

The workspace contains four packages:

| Directory | Package | Responsibility |
| --- | --- | --- |
| `kernel/` | `kernel` | Protocol kernel: coin, assets, transactions, blocks, consensus, ledger, genesis |
| `crypto/` | `crypto` | Cryptography and shared encoding/hash/scalar primitives |
| `runtime/` | `node` | Storage, RPC, mining, mempool, and P2P |
| `wallet/` | `wallet` | Reusable wallet library and wallet application |

`depend/` contains vendored dependency sources and is excluded from workspace
membership. Protocol modules live under `kernel/src/`. See
[`docs/CRATE_CONSOLIDATION.md`](docs/CRATE_CONSOLIDATION.md)
for package boundaries and compatibility details.

## Build and test

```bash
cargo build --release -p node -p wallet
cargo check --workspace --all-targets
cargo test --workspace
```

The release binaries are `target/release/node` and `target/release/wallet`.

Maintenance can target one package, for example `cargo test -p kernel --locked`.
Node and wallet can also be built and deployed separately:

```bash
cargo build --release -p node --locked
cargo build --release -p wallet --locked
```

Shared library changes require rebuilding the applications that use them.
Consensus or encoding changes also require compatibility review and coordinated
releases where needed. See [package maintenance and deployment](docs/CRATE_CONSOLIDATION.md#package-maintenance-and-deployment)
for scope and validation guidance.

## Run a node

```bash
./target/release/node run \
  --data data/node-1 \
  --p2p 0.0.0.0:6677 \
  --rpc 127.0.0.1:6666
```

Enable mining by adding `--miner QxADDRESS`. A second node can use different
ports and connect with `--peer 127.0.0.1:6677`. Canonical selection uses
cumulative work and a deterministic hash tie-break.

## Wallet

```bash
./target/release/wallet
./target/release/wallet --help
```

The wallet supports balance and history queries, XPQ sends, UTXO consolidation,
native assets and block exploration. Consolidation is an
ordinary self-transfer and remains subject to canonical archival burn and a
miner fee.

## RPC and development

A running node serves interactive documentation at `/docs` and its embedded
OpenAPI 3.1 specification at `/openapi.json`. See [`docs/API.md`](docs/API.md)
and [`dev-tools/`](dev-tools/README.md). RPC uses plain HTTP; keep it on
loopback or a trusted private network. `POST /transaction` accepts canonical
Borsh bytes, not JSON.

## Security and compatibility

- Back up the recovery mnemonic offline. Never commit or share wallet files.
- Mining requires only a public payout address, never a wallet file.
- Wait for canonical confirmations before treating a transaction as final.
- Serialization, proof-of-work, genesis, and consensus changes can require an
  explicit database migration or chain reset.

The canonical repository is
[`XPARQ-Labs/XPARQ-2`](https://github.com/XPARQ-Labs/XPARQ-2). Existing commit
history is intentionally retained; see the consolidation document for details.

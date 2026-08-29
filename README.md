# XPARQ

XPARQ is a Rust proof-of-work blockchain workspace with an XPQ UTXO ledger,
QCash bearer files, a TCP peer-to-peer node, HTTP RPC, and an interactive
wallet.

The workspace currently targets Rust 1.90 and uses the Rust 2024 edition.

## Workspace layout

- `common/`: canonical codec and shared primitives
- `crypto/`: hashing, addresses, Argon2id PoW, and signatures
- `coin/`: XPQ amounts and coin identifiers
- `qcash/`: QCash bearer-file types and validation
- `transaction/`: canonical transaction intents and authorization
- `blockchain/`: blocks, headers, and canonical chain structures
- `consensus/`: PoW, emission, WBDA, transaction, fork, and reorg rules
- `ledger/`: canonical XPQ and QCash state
- `genesis/`: frozen network genesis identity
- `xparq/`: public core facade
- `runtime/`: `node` binary, storage, RPC, mining, and P2P
- `wallet/`: reusable wallet library and `wallet` binary
- `extension/asset/`: wrapped-asset primitives for Bitcoin, Ethereum, and Solana
- `extension/bridge/`: bridge-facing network primitives outside the consensus kernel
- `extension/`: facade and parent directory for optional extension crates
- `depend/`: local dependency sources; excluded as a workspace member

Core exposes only consensus-neutral extension primitives through
`xparq::extension`: bounded canonical calls, extension identifiers, state-root
commitments, namespaced state capabilities, and the validate/apply lifecycle.
Asset, bridge, and future DEX primitives remain owned by their extension crates.
`xparq-ledger::ExtensionStateSet` stages writes per extension namespace, computes
the canonical host-owned root, produces deterministic rollback journals, and
commits no state when validation, apply, or root verification fails. The
aggregate post-extension root is committed by `block.header.state_root`; an
empty extension state uses the zero root.

## Build

Build the node and wallet in release mode:

```bash
cargo build --release -p xparq-runtime -p wallet
```

The binaries are produced at:

```text
target/release/node
target/release/wallet
```

Run the workspace checks:

```bash
cargo check --workspace
cargo test --workspace
```

## Run a local node

Start a node with RPC on `127.0.0.1:6666` and P2P on port `6677`:

```bash
./target/release/node run \
  --data data/node-1 \
  --p2p 0.0.0.0:6677 \
  --rpc 127.0.0.1:6666
```

Enable mining by supplying a canonical checksummed `0x` payout address:

```bash
./target/release/node run \
  --data data/node-1 \
  --p2p 0.0.0.0:6677 \
  --rpc 127.0.0.1:6666 \
  --miner 0xADDRESS_WITH_CHECKSUM
```

Connect another local node with `--peer` and different ports/data directory:

```bash
./target/release/node run \
  --data data/node-2 \
  --p2p 0.0.0.0:7677 \
  --rpc 127.0.0.1:7666 \
  --peer 127.0.0.1:6677
```

Nodes may temporarily have different tips while mining. Canonical selection is
based on greatest cumulative work with a deterministic hash tie-break, so
valid peers converge after the stronger branch propagates.

## Wallet

Launch the interactive wallet:

```bash
./target/release/wallet
```

The menu supports wallet creation/restoration, balance, canonical transaction
history, UTXO tracking, XPQ transfers, QCash operations, and block explorer
queries.

Useful direct commands:

```bash
./target/release/wallet address --wallet wallet.json
./target/release/wallet balance --wallet wallet.json --rpc 127.0.0.1:6666
./target/release/wallet history --wallet wallet.json --rpc 127.0.0.1:6666
./target/release/wallet utxos --wallet wallet.json --rpc 127.0.0.1:6666
```

Transaction history hides mining emissions by default and displays canonical
height, confirmations, direction, transaction type, amount, transaction ID,
block hash, and canonical serialized transaction size in bytes. The node and
wallet must both be rebuilt and restarted after an RPC format change.

The UTXO tracker uses the paginated `/account/<address>` wallet endpoint and
shows each CoinId as `available` or `reserved`. CoinIds use the
case-sensitive `XPQ:` prefix followed by 64 hexadecimal characters. Public
explorer address queries remain aggregate/activity-only and do not expose UTXO
lists.

## QCash

QCash files are bearer credentials backed by canonical QCash UTXOs. Anyone
who obtains a valid unspent file can authorize its consumption. Never print,
commit, upload, or share a `.QCash` file.

Filenames describe the amount, for example `10XPQ.QCash`. When multiple files
have the same amount, the wallet uses `10XPQ(2).QCash`, `10XPQ(3).QCash`, and so
on. Renaming does not change the bearer identity stored inside the file.

Interactive operations include:

- withdraw XPQ into QCash;
- full or partial redeem to an XPQ address;
- split one QCash input into multiple outputs;
- merge multiple QCash inputs.

For a split, one requested amount is sufficient. The wallet automatically
creates a fresh QCash change output from the remainder:

```text
input:  2,000 XPQ
output:   100 XPQ
change: 1,900 XPQ
```

Keep input QCash files until the corresponding transaction is canonically
confirmed. QCash files are created with owner-only `0600` permissions on Unix.

## RPC separation

Interactive API documentation is available from a running node at `/docs`.
The machine-readable OpenAPI 3.1 specification is served at `/openapi.json` and
is also tracked in [`docs/openapi.json`](docs/openapi.json). See
[`docs/API.md`](docs/API.md) for transaction encoding and compatibility notes.
Developers creating native assets or WASM extensions should start with the
[`dev-tools/`](dev-tools/README.md) guide.

- `/status`: canonical tip and node status
- `/balance/<address>`: aggregate wallet balance without UTXO pagination
- `/account/<address>`: wallet-only balance and paginated UTXO selection data
- `/explorer/address/<address>`: aggregate balance and canonical activity
- `/explorer/transaction/<transaction-id>`: confirmed transaction details
- `/blocks/latest`: recent block information
- `/block/<height>`: canonical block by height

RPC currently uses plain HTTP. Keep wallet RPC on loopback or a trusted private
network.

## Security notes

- Back up the recovery mnemonic offline; `wallet.json` is created atomically
  with `0600` permissions on Unix and is sensitive.
- Mining needs only the public payout address, never the wallet file.
- Do not treat a freshly mined transaction as final; wait for confirmations.
- Protocol, PoW, serialization, genesis, or consensus-parameter changes can
  require a chain/database reset or an explicit migration.

XPARQ is under active development. Review consensus and storage changes before
using it with assets of real value.

Signed wallet transactions are submitted to node RPC automatically. Use
`--offline` only when canonical transaction hex is needed. This migration uses
P2P v1, redb schema v1, snapshot v1, and chain-spec v1; old node data and peers
are intentionally incompatible.

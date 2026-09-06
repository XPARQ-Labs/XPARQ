# Workspace layout and compatibility

The root workspace contains four packages:

| Package | Directory | Responsibility |
| --- | --- | --- |
| `kernel` | `kernel/` | Canonical coin and asset types, transactions, blocks, consensus, ledger, and genesis |
| `crypto` | `crypto/` | Cryptography, canonical encoding, hashes, and scalar primitives |
| `node` | `runtime/` | Storage, networking, RPC, mempool, and mining |
| `wallet` | `wallet/` | Wallet library, keys, transaction construction, and user interface |

Dependencies point downwards:

```text
node / wallet -> kernel -> crypto
```

Vendored sources under `depend/` are excluded from workspace membership.

## Unified UTXO model

`SpendIntent` signs either a Coin spend consuming `CoinHash` inputs or an asset
spend consuming `AssetShareHash` inputs. Asset registration, minting, and
burning remain native `AssetInstruction` operations because they change asset
metadata or supply.

Coin and asset-share UTXOs live in `LedgerState.utxos`. Both Coin and asset
shares are controlled only by account addresses. `AssetState` stores metadata,
supply, and operation nonces.

## Compatibility

Removing the former extension transaction, state, ownership, and WASM formats
is a consensus and canonical-encoding change. `CHAIN_SPEC_VERSION` is 6, so
older databases, snapshots, blocks, and peers require an explicit migration or
a coordinated chain reset.

Validation commands:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

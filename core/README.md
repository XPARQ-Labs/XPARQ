# XPARQ Core

`core/` is the `xparq` library crate. It contains consensus-critical data
types and validation rules; it does not run a network service or provide a
wallet executable.

## Responsibilities

- canonical block and protocol-transaction encoding;
- Argon2id proof of work, WBDA difficulty, rewards, and cumulative chainwork;
- single-authority ML-DSA signatures on mainnet/testnet and experimental SQIsign on devnet;
- owned-XPQ and QCash UTXO state transitions;
- state commitments, proofs, genesis artifacts, snapshots, and rollback;
- cumulative-work fork choice and checkpoint-aware reorganization rules.

The node-specific database, P2P swarm, mempool policy, HTTP/gRPC servers, and
mining loop live in `node/`. Wallet files, mnemonic handling, transaction
construction, and the interactive CLI live in `wallet/`.

Authorization uses one registered public key per account. Signature-scheme
transitions are height-gated consensus policy, with ML-DSA active on
mainnet/testnet and the SQIsign Level 5 blockchain-test backend available only
on devnet.

## Source layout

```text
core/
├── src/block/         blocks, headers, Merkle commitments, size limits
├── src/consensus/     PoW validation, WBDA, rewards, monetary units
├── src/crypto/        hashes, addresses, ML-DSA, SQIsign candidate adapter
├── src/genesis/       frozen network parameters and authenticated artifacts
├── src/ledger/        transitions, fork choice, reorg, proofs, invariants
├── src/qcash/         QCash amounts, commitments, and bearer-file formats
├── src/state/         account, XPQ UTXO, QCash UTXO, state commitments
├── src/transaction/   transfer and QCash protocol envelopes
├── benches/           core and SQIsign benchmarks
├── examples/          validation benchmark
└── fuzz/              separate cargo-fuzz workspace
```

## Network features

Exactly one network profile must be active:

```bash
# Mainnet is the default.
cargo check -p xparq --locked

cargo check -p xparq --no-default-features --features testnet
cargo check -p xparq --no-default-features --features devnet
```

`devnet` enables the experimental SQIsign Level 5 blockchain-test backend.
Mainnet and testnet continue to use ML-DSA-44. Never combine network features
or reuse a database across differently compiled profiles.

## Tests and benchmarks

```bash
cargo test -p xparq --locked
cargo test -p xparq --doc --locked
cargo bench -p xparq --bench core_consensus
cargo run --release -p xparq --example validation_benchmark
```

SQIsign validation and fuzzing have separate instructions in
[`depend/sqisign/sqisign-improvement.md`](../depend/sqisign/sqisign-improvement.md)
and [`FUZZING.md`](../FUZZING.md).

Any modification to canonical serialization, domain strings, network
parameters, genesis identity, state commitments, PoW, WBDA, rewards, maturity,
or fork choice is a consensus change and requires explicit compatibility work.

# Paqus

Paqus is an experimental proof-of-work blockchain protocol focused on
deterministic execution, post-quantum authorization, independently verifiable
state, and transferable QCash bearer value. This crate contains the consensus
types and validation rules used by Paqus nodes and wallets.

The current implementation is the **Sharksphere** patch of protocol version 1.
The normative implementation-level parameters are documented in
[CHAINSPEC.md](CHAINSPEC.md).

## Protocol Summary

```text
Chain                    Paqus
Chain ID                 747 (mainnet)
Network magic            58 50 51 01 ("XPQ\x01")
Asset                    XPQ
Smallest unit            paqus
Decimals                 6
Consensus                proof of work, greatest cumulative chainwork
Proof of work            Argon2id, 64 MiB, 1 iteration, 4 lanes
Difficulty               Argon2id WBDA, weight-based
Block size limit         2 MiB
Block weight limit       2 MiB
Confirmation depth       2 blocks
Finality boundary        5 blocks
Mining reward maturity   50 blocks
QCash redeem delay      1 block after withdrawal
Initial block subsidy    15 XPQ
Tail emission            0.85 XPQ from height 400,000
Genesis premine          none
```

Genesis is frozen at height 0. Every node validates the same genesis identity
and follows the valid branch with the greatest cumulative proof of work.

Network chain IDs are `707` for devnet, `717` for testnet, and `747` for
mainnet. These IDs are consensus identities and must not be mixed between
network databases.

## Repository Scope

The crate provides:

- canonical Borsh encoding and domain-separated SHA3-256 hashes;
- ML-DSA-44 key generation, signatures, and parallel dual-signature
  verification;
- `P1...` ML-DSA account addresses bound to two authorization public keys
  (`PX1...` is reserved for the inactive SQIsign Level 5 candidate);
- unified transfers containing between 1 and 64 outputs;
- QCash withdrawal, bearer files, redeems, and authenticated UTXO state;
- blocks, Argon2id proof of work, WBDA difficulty, rewards, and chainwork;
- atomic ledger transitions, rollback, bounded reorganization, and invariants;
- account and QCash state proofs;
- frozen-genesis header-chain and checkpoint verification;
- authenticated snapshot and checkpoint artifacts.

Networking, RPC, mining orchestration, mempool policy, dynamic fee rates,
snapshot transport, and database storage belong to the separate node crate.
Those policies are not consensus parameters unless explicitly stated in the
chain specification.

## Accounts and Dual Authorization

An address is derived from an ordered owner/auth ML-DSA-44 public-key pair.
Both signatures are required by default.

The first outgoing transaction from an account carries both public keys. After
successful validation, the ledger stores them in `AccountAuthorization`.
Subsequent transactions carry only the two signatures and the node resolves
both public keys from authenticated account state. This avoids repeating
2,624 bytes of public-key material in every transaction.

Receiving funds does not require prior account registration. A new address can
receive XPQ before its authorization keys are present in state; keys are
registered when that account spends for the first time.

## Transfers

There is one transfer representation:

```rust
Transaction {
    from,
    outputs: Vec<TransferOutput>,
    last_state,
}
```

A transfer must have 1–64 non-zero outputs. Recipients must be unique and may
not equal the sender. A one-output transfer is therefore the canonical
replacement for the former single-transfer form. Shared signatures and common
transaction fields make multi-output transfers substantially smaller than
multiple independent transfers.

Fees are not a core consensus field. Relay, mempool-market, and miner minimum
fee rates in `paqus/vByte` are node policy and can be configured independently.

## Transaction Lifecycle

For a transaction included at height `H`:

```text
H       included, still reorg-sensitive
H + 2   confirmed
H + 5   finalized by the local reorg boundary
```

Normal transfer credits and QCash redeem credits become spendable at
`H + 2`. Coinbase transaction fees use the same confirmation delay, while the
block subsidy matures after 50 blocks.

“Finalized” here means the protocol rejects a reorganization crossing its
configured finality boundary. It is not proof-of-stake or BFT finality.

## QCash

QCash moves value between the account model and a separate authenticated UTXO
set:

```text
account XPQ --withdraw--> QCash bearer UTXO
QCash bearer UTXO --redeem--> account XPQ
```

A withdrawal included at height `H` creates active off-chain bearer coins.
They may be redeemed starting at `H + 1`. A successful redeem consumes the
QCash UTXO immediately and creates an account credit that becomes spendable at
`redeem height + 2`.

Each `.XPQ` file contains an opaque 32-byte coin ID, denomination, and private
opening secret. The file is bearer value and must be protected like physical
cash. Reorganizations are handled by canonical ledger rollback: outputs made
on disconnected branches are removed and redeems disconnected from the
canonical chain restore their consumed UTXOs.

## Authenticated Fast Sync and Proofs

The consensus crate verifies complete header chains from the frozen genesis,
including linkage, expected WBDA difficulty, Argon2id proof of work, block
weight commitments, and cumulative chainwork. The node can compare
independently supplied valid header chains, choose the greatest-work tip,
download the snapshot bound to that checkpoint, and activate it only when its
state commitments match.

Snapshot providers are therefore data sources, not trusted consensus
authorities. Security still depends on obtaining the real greatest-work chain;
nodes and light clients should compare multiple independently operated peers
to reduce eclipse risk.

Account and QCash proof bundles support trusted header checkpoints. After a
wallet has validated and retained a checkpoint, it can verify only the header
extension after that checkpoint instead of repeatedly carrying headers from
genesis.

## Encoding and Compatibility

Consensus objects use canonical little-endian Borsh through `codec.rs`.
Direct serialization must not be used for consensus hashes, signatures,
network payloads, or persisted consensus objects.

The transaction hash commits to the signed protocol envelope. Blocks commit to
the ordered transaction Merkle root, the resulting protocol state root, the
chain commitment, and the canonical block weight.

Protocol vectors protect canonical bytes and hash results. Changing a
consensus structure, field order, domain string, parameter, or frozen vector is
a consensus change even if the numeric protocol-version field is unchanged.

## Build and Test

```bash
cargo build
cargo test
cargo test --doc
cargo bench
cargo run --release --example validation_benchmark
```

Decoder fuzzing requires nightly Rust and `cargo-fuzz`:

```bash
cargo +nightly fuzz run decode_signed_transaction
cargo +nightly fuzz run decode_block
```

## Safety Rules

- State transitions must be deterministic and atomic.
- Failed transactions and blocks must not mutate canonical state.
- Both authorization signatures must validate against the account’s keys.
- New account addresses may receive value without prior key registration.
- XPQ value must exist in account state or active QCash UTXOs, never both.
- Fork choice uses validated cumulative work, not peer claims or height alone.
- Snapshot state must match its authenticated header checkpoint.
- Decoders must reject malformed, oversized, and trailing data.
- Consensus-domain strings and typed hashes must not be mixed.

## Status

Paqus is under active development. The current 1/2/5 lifecycle values are
development parameters and protocol compatibility may change before a stable
release. Do not use this software to secure production value without
independent review.

Protocol discussion: [Paqus Matrix room](https://matrix.to/#/#paqus:matrix.org)

# XPARQ

XPARQ is a proof-of-work blockchain protocol focused on deterministic
execution, post-quantum authorization, independently verifiable state, and
transferable QCash bearer value.

## Monorepo Layout

This repository is one Cargo workspace:

```text
XPARQ/
├── Cargo.toml                 workspace manifest and shared dependencies
├── core/                      consensus primitives (`xparq`)
├── node/                      node, P2P, RPC, and application configuration
├── wallet/                    reusable wallet library and wallet CLI
└── depend/                    standalone vendored-dependency workspace
```

Run workspace commands from the repository root, for example
`cargo check --workspace --locked` or `cargo test --workspace --locked`.
`core`, `node`, and `wallet` are the three primary workspace packages.
Dependency versions and path overrides are controlled by the root manifest.
`depend` has its own virtual workspace manifest and is excluded from the
application workspace; vendored packages retain the upstream manifests Cargo
needs to compile them.

The current implementation is the **Sharksphere** patch of protocol version 1.
Consensus parameters are defined by the `core` crate and summarized below.
Operator and component documentation is organized as follows:

- [Mining and node tutorial](tutorial.md)
- [Core crate](core/README.md)
- [Node binary](node/README.md)
- [Wallet library and CLI](wallet/README.md)
- [Fuzzing](FUZZING.md)
- [Vendored dependency boundary](depend/README.md)

## Protocol Summary

```text
Chain                    XPARQ
Chain ID                 747
Network magic            58 50 51 01 ("XPQ\x01")
Asset                    XPQ
Smallest unit            paqs
Decimals                 6
Consensus                proof of work, greatest cumulative chainwork
Proof of work            Argon2id, 64 MiB, 1 iteration, 2 lanes
Difficulty               Argon2id WBDA, weight-based
Block size limit         5 MiB
Block weight limit       5 MiB
Confirmation depth       2 blocks
Finality boundary        5 blocks
Mining reward maturity   50 blocks
QCash redeem delay      1 block after withdrawal
Base block subsidy       10 XPQ
Minimum block subsidy    1 XPQ
Maximum block subsidy    20 XPQ
Reward adjustment        1 XPQ per WBDA epoch
Genesis premine          none
```

Genesis is frozen at height 0. Every node validates the same genesis identity
and follows the valid branch with the greatest cumulative proof of work.

Network chain IDs are `707` for devnet, `717` for testnet, and `747` for
mainnet. These IDs are consensus identities and must not be mixed between
network databases.

## WBDA Difficulty and Block Reward

XPARQ evaluates difficulty and block subsidy once per completed WBDA epoch of
2,048 blocks. Utilization is the average canonical serialized block weight in
the completed epoch divided by the fixed 5 MiB target. Equivalently, this is
the total block weight across the epoch divided by `2,048 * 5 MiB` (`10 GiB`):

```text
utilization = average block weight / 5 MiB
            = total epoch block weight / 10 GiB

below 30%       difficulty +1, subsidy +1 XPQ
30% through 70% difficulty unchanged, subsidy unchanged
above 70%       difficulty -1, subsidy -1 XPQ
```

The 30% and 70% boundaries are part of the unchanged zone. Difficulty cannot
fall below `1`, and the subsidy is clamped to `1..=20 XPQ`. The first epoch,
blocks `1..=2,048`, uses the base subsidy of 10 XPQ. Its measured utilization
determines the difficulty and subsidy beginning at block `2,049`; every block
within the following epoch uses that same result.

Only the subsidy valid for the current epoch is issued in its coinbase. If the
subsidy changes from 10 XPQ to 9 XPQ, the miner receives 9 XPQ and the remaining
1 XPQ is never created. It is not burned after issuance and is not allocated to
the protocol, a treasury, a foundation, a vault, developers, or any other
recipient. A later increase similarly authorizes only the new subsidy for new
blocks; it does not draw from a reserve of previously unissued XPQ.

## Repository Scope

The crate provides:

- canonical Borsh encoding and domain-separated SHA3-256 hashes;
- network-selected post-quantum signatures: ML-DSA-44 on mainnet/testnet and
  SQIsign on devnet;
- account addresses bound to an ordered pair of authorization public keys;
- owned-XPQ UTXO transfers with deterministic coin IDs and change outputs;
- QCash withdrawal, bearer files, redeems, and authenticated UTXO state;
- blocks, Argon2id proof of work, WBDA difficulty, rewards, and chainwork;
- atomic ledger transitions, rollback, bounded reorganization, and invariants;
- authorization-account and QCash state proofs, with XPQ UTXO roots committed
  into every protocol state root;
- frozen-genesis header-chain and checkpoint verification;
- authenticated snapshot and checkpoint artifacts.

Networking, RPC, mining orchestration, mempool policy,
snapshot transport, and database storage belong to the separate node crate.
Those policies are not consensus parameters unless explicitly stated in the
chain specification.

## Node P2P Transport

The node uses a persistent `libp2p 0.54` swarm over TCP. Peer sessions are
authenticated and encrypted with Noise, multiplexed with Yamux, kept live by
periodic ping and Identify traffic, and discovered through the Kademlia routing
table. XPARQ application requests retain canonical Borsh payloads under the
`/xparq/borsh/1` request-response protocol; libp2p owns connection lifecycle,
stream framing, backpressure, and concurrent streams.

Each node stores its stable Ed25519 peer identity as `p2p-identity.key` inside
the selected network database directory. The private identity file is created
with owner-only permissions on Unix systems.

## Accounts and Dual Authorization

An address is derived from an ordered owner/auth public-key pair using the
chain identifier and signature scheme selected by the compiled network. Its
canonical text form is lowercase Bech32 with the `x` HRP (`x1...`);
uppercase, mixed-case, and other HRPs are rejected. Both signatures are
required by default.

The first outgoing transaction from an account carries both public keys. After
successful validation, the ledger stores them in `AccountAuthorization`.
Subsequent transactions carry only the two signatures and the node resolves
both public keys from authenticated account state. This avoids repeating
2,624 bytes of public-key material in every transaction.

Receiving funds does not require prior authorization registration. `Account`
stores only the address authorization keys; it does not store balance or a
replay counter. An address balance is derived by summing its unspent XPQ
outputs. Replay and double-spend protection comes from consuming each input
coin exactly once.

## Transfers

The wallet presents a single-recipient payment, while the consensus transfer
contains explicit inputs and outputs so it can also carry change and an
optional miner payment:

```rust
Transfer {
    from,
    inputs: Vec<XpqCoinId>,
    outputs: Vec<TransferOutput>,
}
```

`XpqCoinId` is `H("XPARQ_HASH_COIN_V1" || transaction_hash || output_index)`.
The old inputs are removed atomically and every output receives a deterministic
new ID. A typical payment has a recipient output, a change output back to the
sender, and optionally an ordinary `BlockMiner` output selected by the node and
wallet. Core has no fee field or fee accounting rule.

## Transaction Lifecycle

For a transaction included at height `H`:

```text
H       included, still reorg-sensitive
H + 2   confirmed
H + 5   finalized by the local reorg boundary
```

Normal transfer outputs and QCash redeem outputs become spendable at
`H + 2`. The block subsidy matures after 50 blocks.

“Finalized” here means the protocol rejects a reorganization crossing its
configured finality boundary. It is not proof-of-stake or BFT finality.

## QCash

QCash moves value between two distinct UTXO models:

```text
owned XPQ UTXO --withdraw--> QCash bearer UTXO
QCash bearer UTXO --redeem--> owned XPQ UTXO
```

A withdrawal included at height `H` creates active off-chain bearer coins.
They may be redeemed starting at `H + 1`. A successful redeem consumes the
QCash UTXO immediately and creates ordinary XPQ outputs that become spendable
at `redeem height + 2`. The outputs contain exactly one address recipient and
may contain one `BlockMiner` output. Their sum must equal the redeemed QCash
value, so the miner payment is an ordinary output rather than a core fee field.

Each `.QCash` file contains an opaque 32-byte coin ID, denomination, and private
opening secret. The file is bearer value and must be protected like physical
cash. Reorganizations are handled by canonical ledger rollback: outputs made
on disconnected branches are removed and redeems disconnected from the
canonical chain restore their consumed UTXOs.

## Authenticated Fast Sync and Proofs

The consensus crate verifies complete header chains from the configured genesis
(compile-time frozen on mainnet and derived at runtime on testnet/devnet),
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
previous block hash, claimed difficulty, and canonical block weight. Height is
chain-position metadata validated from parent linkage; the miner is identified
by the emission recipient.

Protocol vectors protect canonical bytes and hash results. Changing a
consensus structure, field order, domain string, parameter, or frozen vector is
a consensus change even if the numeric protocol-version field is unchanged.

## Build and Test

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo test -p xparq --doc --locked
cargo bench -p xparq
cargo run --release -p xparq --example validation_benchmark
```

The default build targets mainnet. Select exactly one network profile when
building for testnet or devnet:

```bash
cargo build --workspace --no-default-features --features testnet
cargo build --workspace --no-default-features --features devnet
```

Decoder fuzzing requires nightly Rust and `cargo-fuzz`:

```bash
cd core
cargo +nightly fuzz run decode
cargo +nightly fuzz run decode_block
```

See [FUZZING.md](FUZZING.md) for all fuzz targets and resource bounds.

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

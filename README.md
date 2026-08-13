# XPARQ

XPARQ is a proof-of-work blockchain protocol focused on deterministic
execution, post-quantum authorization, independently verifiable state, and
transferable QCash bearer value.

## Monorepo Layout

This repository contains the primary L1 Cargo workspace:

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
`core`, `node`, and `wallet` are the three primary L1 workspace packages.
Dependency versions and path overrides are controlled by the root manifest.
`depend` has its own virtual workspace manifest and is excluded from the
application workspace; vendored packages retain the upstream manifests Cargo
needs to compile them.

The current implementation is the **Sharksphere** patch of protocol version 1.
Consensus parameters are defined by the `core` crate and summarized below.
Operator and component documentation is organized as follows:

- [Mining and node tutorial](TUTORIAL.md)
- [Core crate](core/README.md)
- [Node binary](node/README.md)
- [Docker deployment](node/README.md#docker)
- [Wallet library and CLI](wallet/README.md)
- [Protocol whitepaper](WHITEPAPER.md)
- [Core decomposition roadmap](ROADMAP.md)
- [Fuzzing](FUZZING.md)
- [Vendored dependency boundary](depend/README.md)

## Protocol Summary

```text
Chain                    XPARQ
Chain ID                 747
Network magic            58 50 51 14 ("XPQ\x14")
Asset                    XPQ
Smallest unit            paqs
Decimals                 6
Consensus                proof of work, greatest cumulative chainwork
Proof of work            Network-bound Argon2id-v1.3, 64 MiB, 1 iteration, 2 lanes, 32-byte output
Difficulty               Argon2id WBDA, weight-based
Block size limit         5 MiB
Block weight limit       5 MiB
Confirmation depth       2 blocks
Transaction finality     5 blocks
Automatic PoW checkpoints disabled; explicit trusted snapshots only
Mining reward maturity   50 blocks
QCash redeem delay      1 block after withdrawal
Base block subsidy       5 XPQ
Minimum block subsidy    0.5 XPQ
Maximum block subsidy    10 XPQ
Reward adjustment        0.1 XPQ per WBDA epoch
Genesis premine          none
```

Genesis is frozen at height 0. Every node validates the same genesis identity
and follows the valid branch with the greatest cumulative proof of work.
The frozen identity contains only the stable, empty height-zero block header.
Tunable consensus policy such as rewards, WBDA thresholds, block limits,
maturity depths, address size, and active PoW parameters is committed and
checked separately through the chain specification and peer handshake; changing
those values does not silently redefine the frozen genesis block.

Version 0.2.12 establishes a new chain-spec and peer-compatibility boundary for
the 5 XPQ base subsidy policy and 20-byte addresses without redefining the
frozen empty genesis header. Databases, snapshots, checkpoints, wallets,
addresses, and blocks from incompatible address builds or version 0.2.11 and
earlier are not compatible. Operators must start with a fresh network database
and regenerate or restore wallets from their mnemonic under the new format;
mixed peers are intentionally rejected during P2P compatibility checks.

The active PoW construction is also network-bound through its chain ID and
parent-derived salt. Blocks mined with the former constant-salt/64-byte-output
construction are incompatible; operators must start from a fresh database or
an explicitly authenticated snapshot produced by this construction.
Development databases written by a build that generated automatic buried-WBDA
checkpoints must also be reset; the old database format did not record enough
checkpoint provenance to distinguish a local checkpoint from an explicitly
trusted snapshot anchor.

Network chain IDs are `707` for devnet, `717` for testnet, and `747` for
mainnet. These IDs are consensus identities and must not be mixed between
network databases.

## WBDA Difficulty and Block Reward

XPARQ evaluates difficulty and block subsidy once per completed WBDA epoch of
4,100 blocks. Utilization is the average canonical serialized block weight in
the completed epoch divided by the fixed 5 MiB target. Equivalently, this is
the total block weight across the epoch divided by `4,100 * 5 MiB`:

```text
utilization = average block weight / 5 MiB
            = total epoch block weight / (4,100 * 5 MiB)

below 40%       difficulty +1, subsidy +0.1 XPQ
40% through 60% difficulty unchanged, subsidy unchanged
above 60%       difficulty -1, subsidy -0.1 XPQ
```

The 40% and 60% boundaries are part of the unchanged zone. Difficulty cannot
fall below `1`, and the subsidy is clamped to `0.5..=10 XPQ`. The first epoch,
blocks `1..=4,100`, uses the base subsidy of 5 XPQ. Its measured utilization
determines the difficulty and subsidy beginning at block `4,101`; every block
within the following epoch uses that same result.

Only the subsidy valid for the current epoch is issued by its emission
transaction. If the subsidy changes from 5 XPQ to 4.9 XPQ, the miner receives
4.9 XPQ and the remaining 0.1 XPQ is never created. It is not burned after
issuance and is not allocated to the protocol, a treasury, a foundation, a
vault, developers, or any other recipient. A later increase similarly
authorizes only the new subsidy for new blocks; it does not draw from a reserve
of previously unissued XPQ.

## Repository Scope

The crate provides:

- canonical Borsh encoding and domain-separated SHA3-256 hashes;
- single-authority, network-selected post-quantum signatures: ML-DSA-44 on mainnet/testnet and
  SQIsign on devnet;
- account addresses bound to one authorization public key;
- owned-XPQ UTXO transfers with deterministic coin IDs and change outputs;
- QCash withdrawal, bearer files, redeems, and authenticated UTXO state;
- blocks, Argon2id proof of work, WBDA difficulty, rewards, and chainwork;
- atomic ledger transitions, incremental checkpoint-aware reorganization, and invariants;
- authorization-account and QCash state proofs, with XPQ UTXO roots committed
  into every protocol state root;
- frozen-genesis header-chain and checkpoint verification;
- authenticated snapshot and checkpoint artifacts.

Networking, RPC, mining orchestration, mempool policy,
snapshot transport, and database storage belong to the separate node crate.
Those policies are not consensus parameters unless explicitly stated in the
chain specification.

## Current Node Implementation Status

The workspace application packages and binaries are named `node` and
`wallet`. The retired package and binary names must not be used in build,
release, or operator commands.

The node currently provides:

- a bounded 256-job cryptographic verification queue with explicit inline
  fallback when saturated;
- an in-memory, height-scoped stateless authorization cache capped at 4,096
  successful verification entries;
- a bounded 128-job blocking state pipeline for transaction validation,
  mining submission, and LMDB-backed RPC work;
- parallel block-range download, parallel stateless prevalidation, bounded
  result buffering, and ordered state application during synchronization;
- account and XPQ/QCash dirty-state persistence in the same atomic LMDB
  transaction as the accepted block, with a full state snapshot at genesis
  and every 2,048 blocks;
- a recent-block cache capped at 32 blocks and 64 MiB, storing one block object
  with a secondary hash-to-height index and falling back to canonical chain
  storage for evicted historical blocks;
- Prometheus metrics for RPC latency, state and crypto queue pressure, sync
  download/verification/application latency, and block-cache occupancy.

These caches and queues are process-local operational mechanisms. They do not
change consensus validity, canonical hashes, state roots, fork choice, or the
LMDB atomic-commit boundary.

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

## Accounts and Single-Key Authorization

An address is the last 20 bytes of SHA3-256 over one signing public key. Its
text form is 40-character lowercase Bech32 with the `z` HRP (`z1...`);
uppercase, mixed-case, and other HRPs are rejected. Spending requires one
consensus signature.

The first outgoing transaction from an account carries its public key. After
successful validation, the ledger stores it in `AccountAuthorization`.
Subsequent transactions carry only one signature and the node resolves the
public key from authenticated account state.

Receiving funds does not require prior authorization registration. `Account`
stores only the address authorization key; it does not store balance or a
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
sender, and an ordinary `BlockMiner` output selected by the node and wallet.
Core has no separate fee field or minimum-fee consensus rule. The standard node
applies its configured per-vbyte relay rate uniformly to every transaction
family. The default is one paqs (the smallest XPQ unit) per virtual byte, while
an operator may explicitly configure zero.

## Transaction Lifecycle

For a transaction included at height `H`:

```text
H       included, still reorg-sensitive
H + 2   confirmed
H + 5   finalized transaction lifecycle status
```

Normal transfer outputs and QCash redeem outputs become spendable at
`H + 2`. The block subsidy matures after 50 blocks.

“Finalized” at depth 5 is only the transaction lifecycle and wallet/API
confidence status. It does not prevent a greater-work reorganization. Nodes do
not turn locally observed 4,100-block boundaries into hard checkpoints. A hard
checkpoint exists only when the operator explicitly activates an authenticated
release snapshot or checkpoint trust anchor.

## QCash

QCash moves value between two distinct UTXO models:

```text
owned XPQ UTXO --withdraw--> QCash bearer UTXO
QCash bearer UTXO --redeem--> owned XPQ UTXO
QCash bearer UTXO --split----> multiple QCash bearer UTXOs
```

A withdrawal included at height `H` creates active off-chain bearer coins.
They may be redeemed starting at `H + 1`. A successful redeem consumes the
QCash UTXO immediately and creates ordinary XPQ outputs that become spendable
at `redeem height + 2`. The outputs contain exactly one address recipient and
may contain one `BlockMiner` output. A partial redeem may also create QCash
change in the same transaction. A pure split creates two or more independently
redeemable QCash outputs without an address-recipient output. Address outputs,
QCash outputs, and any miner output must sum to the consumed QCash
value, so partial redeem and split each pay for one transaction.

Each `.QCash` file contains an opaque 32-byte coin ID, exact amount in paqs, and
a private opening secret. Names use `NominalXPQ_<64_HEX_COIN_ID>.QCash`, including
fractional values such as `29.9XPQ_<64_HEX_COIN_ID>.QCash`. The file is bearer
value and must be protected like physical cash. Reorganizations are handled by
canonical ledger rollback: outputs made on disconnected branches are removed
and redeems disconnected from the canonical chain restore their consumed
UTXOs.
Transactions from a disconnected block are revalidated automatically and
returned to the mempool when they remain valid, including QCash redeems and
splits. The wallet retains the source bearer file after mempool acceptance;
ledger state determines whether it is still spendable. New partial-redeem or
split files are retained only after the node accepts the transaction.
The active ledger rolls back only the losing suffix to the common ancestor and
then applies only the winning suffix. Canonical database indexes are replaced
for those affected heights rather than rebuilt from genesis, and persisted
per-block undo state keeps this path available after restart.

`QCashRedeemed` events expose the on-chain recipient `amount` and the total
`qcash_change_amount` recreated as bearer outputs. Pure splits emit
`QCashSplit`. Manual on-chain QCash recovery and its legacy event are not part
of the active protocol.

## Authenticated Fast Sync and Proofs

The consensus crate verifies complete header chains from the configured genesis
(compile-time frozen on mainnet and derived at runtime on testnet/devnet),
including linkage, expected WBDA difficulty, Argon2id proof of work, block
weight commitments, and cumulative chainwork. The node can compare
independently supplied valid header chains, choose the greatest-work tip,
download the snapshot bound to that checkpoint, and activate it only when its
state commitments match.

Ordinary peer synchronization validates linkage, branch-local WBDA difficulty,
and Argon2id proof of work for every received header before requesting the
corresponding block bodies. Sync windows and body batches are bounded, and the
orphan pool has independent count, height-distance, and expiry limits.

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
- The authorization signature must validate against the account’s registered key.
- New account addresses may receive value without prior key registration.
- XPQ value must exist in account state or active QCash UTXOs, never both.
- Fork choice uses validated cumulative work, not peer claims or height alone.
- Snapshot state must match its authenticated header checkpoint.
- Decoders must reject malformed, oversized, and trailing data.
- Consensus-domain strings and typed hashes must not be mixed.

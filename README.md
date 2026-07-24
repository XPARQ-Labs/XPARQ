# Paqus Core

Consensus library for the Paqus proof-of-work blockchain. The crate provides
canonical encoding, post-quantum signatures, transactions, blocks, ledger state,
QCash UTXOs, fork choice, reorg handling, rewards, and frozen genesis rules.

Paqus currently uses protocol version 1. Consensus changes must remain
deterministic across every node.

## Current Protocol

```text
Chain:                     Paqus
Chain ID:                  747
Coin:                      XPQ
Smallest unit:             paqus
Decimals:                  6
Protocol stage:            Mainnet
Protocol version:          1
Proof of work:             SHA3-512
Difficulty:                per-block ASERT, starting at 1 bit
Target block time:         5 minutes
Transaction confirmation: 5 blocks  (~25 minutes)
Hard finality:             50 blocks (~4 hours 10 minutes)
Block reward maturity:     100 blocks (~8 hours 20 minutes)
QCash maturity:            50 blocks (~4 hours 10 minutes)
Block subsidy:             25 XPQ
Tail emission:             0.747 XPQ from height 525,600
Genesis premine:           none
```

Full-node storage version 2 is required. Databases created under a different
protocol or genesis identity must not be reused without an explicit migration.

## Architecture

- `codec.rs` is the public boundary for canonical Borsh encoding and decoding.
- `crypto/` provides SHA3 hashing, ML-DSA-87 signatures, and `PX1...` addresses.
- `transaction/` contains transfer and QCash transaction envelopes.
- `block/` contains version-1 SegWit blocks, Merkle roots, and witness roots.
- `consensus/` contains proof-of-work, ASERT, rewards, and supply rules.
- `ledger/` applies atomic state transitions, fork choice, finality, and reorgs.
- `state/` contains account state and the QCash UTXO set.
- `genesis/` defines chain identity and dynamic mined-genesis construction.
- `event/` derives protocol receipts from successful canonical transitions.

Consensus data must be encoded through `codec.rs`. Do not call Borsh
serialization directly for hashes, signatures, network payloads, or stored
consensus objects.

## Monetary Units

```text
1 XPQ = 1,000,000 paqus
```

Ordinary transfers and mining rewards use the account model. QCash bearer value
uses a separate UTXO set. Economic supply is the sum of account balances and all
active QCash UTXOs, preventing value from existing in both models at once.

## Transactions and SegWit

Paqus has two transaction families:

- `Transfer` moves XPQ between accounts.
- `QCash` withdraws account value into bearer UTXOs or deposits bearer UTXOs
  into an account.

The transaction ID (`txid`) commits to the payload and remains stable when the
witness changes. The witness transaction ID (`wtxid`) commits to the complete
signed envelope. Blocks commit to both a payload Merkle root and a witness root.

Transaction outputs become available at:

```text
block height + CONFIRMATION_DEPTH
```

Coinbase fees follow confirmation maturity. The block subsidy becomes available
at:

```text
block height + BLOCK_REWARD_MATURITY
```

## QCash UTXO

A QCash withdrawal creates one `QCashUtxo` for each denomination. Each output
has a canonical:

```text
QCashOutPoint {
    transaction_hash,
    output_index,
}
```

`CashCoinId` is derived from the withdrawal transaction and canonical output.
New outputs are `Pending` and become `Spendable` after 50 blocks.

A bearer `.XPQ` file contains:

- the complete 32-byte UTXO identifier;
- its denomination;
- a private opening secret.

Deposit authorization is bound to the recipient and verified with ML-DSA. A
successful deposit removes the UTXO immediately and creates an account credit
locked for 50 blocks. Reusing the same file is rejected as unknown or already
spent.

Anyone holding a valid, unspent `.XPQ` file can deposit it into another wallet.
The file must therefore be protected like physical cash. ML-KEM is not used to
bind ownership; encryption used while transporting a file is a wallet or network
transport concern, not a consensus ownership rule.

The account state root and QCash UTXO root are domain-separated and combined
into one protocol state root. Block rollback removes outputs created on the
disconnected branch and restores UTXOs consumed by disconnected deposits.

## Blocks and Mining

Genesis is frozen by protocol at height 0 with a canonical hash and no premine.
All nodes must start from that same block; the first miner-created block is
height 1. Nodes with storage from a different genesis are on a different chain
and must be resynchronized from a canonical peer.

Every non-genesis block contains an exact coinbase payment. A block may be
coinbase-only when the mempool is empty. Candidate validation checks:

- canonical version and encoding;
- previous block linkage and timestamp policy;
- expected ASERT difficulty and proof of work;
- transaction and witness roots;
- transaction signatures, nonces, fees, and maturity;
- exact coinbase subsidy and fees;
- the combined account and QCash protocol state root.

Fork choice selects the valid branch with the greatest cumulative work.
Competing branches cannot replace blocks beyond `FINALITY_DEPTH`.

## Hashing and Encoding

Consensus objects use canonical little-endian Borsh under the
`paqus-borsh-le` profile. Hash domains and Rust wrapper types separate block,
transaction, witness, state, event, and proof-of-work hashes.

Canonical compatibility fixtures are enforced by protocol-vector tests. Vector
changes require an explicit consensus decision and must never be regenerated
silently.

## Build and Test

From the core repository root:

```bash
cargo build
cargo test
cargo test --doc
```

Run benchmarks:

```bash
cargo bench
```

Run decoder fuzz targets with nightly Rust:

```bash
cd core
cargo +nightly fuzz run decode_signed_transaction
cargo +nightly fuzz run decode_block
```

Useful environment variables:

```text
PAQUS_FUZZ_MAX_LEN=<bytes>
PAQUS_FUZZ_RUNS=<count>
PAQUS_FUZZ_TIME_SECS=<seconds>
```

## Safety Rules

- State transitions must be deterministic and atomic.
- Failed transactions or blocks must not mutate state.
- Account keys must match their embedded addresses.
- Account credits must sum to the recorded balance.
- QCash value must exist either in accounts or active UTXOs, never both.
- Hash domains and typed hashes must not be mixed.
- Decode helpers must reject malformed, oversized, and trailing data.

## Disclaimer

Paqus is an independent, non-profit blockchain research and development
project. This software is experimental and should be reviewed carefully before
production use.

## Community

Protocol discussion: [Paqus Matrix room](https://matrix.to/#/#paqus:matrix.org)

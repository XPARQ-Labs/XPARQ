# Protocol overview

## Chain identity

| Parameter | Mainnet value |
| --- | --- |
| Chain name | Paqus |
| Patch | Sharksphere |
| Chain ID | 747 |
| Protocol version | 1 |
| Network magic | `58 50 51 01` |
| Genesis height | 0 |
| Genesis hash | `067ce305a89f3879935f4838803d7a699af340f733a2791839eb10c96e8bffab` |

Genesis is the height-0 block. Core consensus does not use human wall-clock
timestamps for genesis identity or block validity.

## Encoding and hashing

Consensus objects use canonical little-endian Borsh. Hashes use SHA3-256 with
typed domain separation. Transaction hashes commit to the signed protocol
envelope.

Do not use general-purpose serialization for consensus hashes, signatures,
network payloads, or persisted consensus objects.

## Blocks

A block is the canonical tuple:

```text
Block(header, body, proof)
```

The header commits to height, previous hash, merkle root, state root, chain
commitment, miner address, difficulty, and block weight. The proof currently
contains the proof-of-work nonce. The body contains genesis allocations,
coinbase, and signed protocol transactions.

## Proof of work and WBDA

| Parameter | Value |
| --- | ---: |
| Algorithm | Argon2id |
| Memory | 65,536 KiB |
| Iterations | 1 |
| Lanes | 4 |
| Difficulty algorithm | `argon2id-wbda-weight-v1` |
| WBDA window | 2,048 blocks |
| Low utilization threshold | 20% |
| High utilization threshold | 80% |
| Difficulty step | 1 |

WBDA is weight based, not time based. It adjusts difficulty at window
boundaries from the average raw canonical block weight over the previous
window. Below 20% average utilization, mining becomes harder by one difficulty
step. Above 80% average utilization, mining becomes easier by one difficulty
step. Header-only recovery cannot derive a WBDA boundary without the block
weights committed by the full blocks.

## Block limits

| Limit | Value |
| --- | ---: |
| Maximum block size | 2 MiB |
| Maximum block weight | 2 MiB |
| Maximum decoded block items | 4,096 |
| Maximum genesis allocations | 4,096 |
| Maximum outputs per Transfer | 64 |
| Maximum QCash withdrawal outputs | 256 |
| Maximum QCash redeem inputs | 4 |

Paqus block weight is the raw canonical serialized block size.

## Monetary policy

The block subsidy is 15 XPQ before height 400,000. From height 400,000 onward,
tail emission is 0.85 XPQ per block. Genesis contains no premine.

## Account state

Accounts carry a canonical AccountStatement. The statement is the sender-side
causal anchor. Incoming transfers update the receiver balance but do not
advance the receiver statement; only self-authorized outgoing account actions
advance that account's statement.

## State and proofs

Blocks commit to protocol state. Account and QCash sparse-state proofs can be
verified against an authenticated header chain. Snapshot activation checks
chain parameters, headers, proof of work, and state commitments.

For the complete normative parameter list, see the repository's
`CHAINSPEC.md`. Source code and frozen vectors remain authoritative.

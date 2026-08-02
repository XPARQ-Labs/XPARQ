# Paqus Chain Specification

This document records the current consensus parameters implemented by the
`paqus` crate. Source code and canonical vectors remain authoritative if this
summary ever differs from the implementation.

## Networks

| Network | Chain name | Chain ID | Coin | Stage | Network magic | Genesis hash |
| --- | --- | ---: | --- | --- | --- | --- |
| Mainnet | `Paqus` | `747` | `XPQ` | `Mainnet` | `58 50 51 01` | `067ce305a89f3879935f4838803d7a699af340f733a2791839eb10c96e8bffab` |
| Testnet | `Paqus Testnet` | `717` | `tXPQ` | `Testnet` | `54 58 50 51` | `1b9032537a04d5afc7a5debecdfbb1cbbd2dbde7dba7bc1c4581e50fc53097fc` |
| Devnet | `Paqus Devnet` | `707` | `dXPQ` | `Devnet` | `44 58 50 51` | `6a91293dbf944a5c36006267819310fac05cfa8d5e6337f63c4f222713dc078f` |

All networks use patch name `Sharksphere` and protocol version `1`. Exactly one
network feature must be enabled: `mainnet`, `testnet`, or `devnet`. Mainnet
uses ML-DSA-44. Testnet mirrors the mainnet signature and transaction format by
also using ML-DSA-44. Devnet uses SQIsign. Network profiles must not share
databases or wallet files.

## Monetary Policy

| Parameter | Value |
| --- | ---: |
| Smallest unit | `paqus` |
| Decimal places | `6` |
| Units per XPQ | `1,000,000` |
| Base block subsidy | `10 XPQ` |
| Minimum block subsidy | `1 XPQ` |
| Maximum block subsidy | `20 XPQ` |
| Epoch subsidy step | `1 XPQ` |
| Mainnet genesis premine | `0 XPQ` |
| Testnet/devnet faucet allocation | `1,000,000,000 XPQ` |
| Testnet/devnet faucet request cap | `1,000 XPQ` |

The first epoch pays `10 XPQ` per block. At each WBDA boundary, the completed
epoch's utilization changes both difficulty and the subsidy for the following
epoch. Subsidy changes by `1 XPQ` and is clamped to `1..=20 XPQ`.

## Cryptography

| Parameter | Value |
| --- | ---: |
| General hash | SHA3-256 |
| Hash length | `32 bytes` |
| Proof-of-work output | `64 bytes` |
| Mainnet/testnet transaction signature | ML-DSA-44 |
| Devnet transaction signature | SQIsign Level 5 |
| Address payload | `20 bytes` |
| Address HRP (all networks) | `P` |

Account addresses commit to an ordered owner/authorization public-key pair and
the active chain ID. Outgoing account transactions require both authorization
signatures. The first spend from an unregistered account carries both public
keys; later spends can resolve the stored keys from account state.

## Blocks and Difficulty

| Parameter | Value |
| --- | ---: |
| Block version | `1` |
| Maximum block size | `5 MiB` |
| Maximum block weight | `5 MiB` |
| Maximum decoded protocol transactions | `4,096` |
| Maximum genesis allocations | `4,096` |
| Proof of work | Argon2id |
| Argon2 memory | `65,536 KiB` |
| Argon2 iterations | `1` |
| Argon2 lanes | `4` |
| Minimum difficulty | `1` |
| Starting difficulty | `1` |
| Difficulty algorithm | `argon2id-wbda-weight-v1` |
| WBDA window | `2,048 blocks` |
| WBDA target block weight | `5 MiB` |
| WBDA low-utilization threshold | `30%` |
| WBDA high-utilization threshold | `70%` |
| WBDA step | `1` |

WBDA adjusts difficulty and reward only at epoch boundaries. It samples the
previous `2,048` block weights against the fixed `5 MiB` target. Below 30%
utilization, difficulty and reward rise by one step. From 30% through 70%
(inclusive), both remain unchanged. Above 70%, difficulty and reward fall by
one step. Difficulty is never below `1`; reward stays within `1..=20 XPQ`.
Genesis at height `0` is not part of an epoch: epoch 1 is heights `1..=2,048`,
and its adjustment first applies to height `2,049`.

Fork choice selects the valid branch with the greatest locally verified
cumulative work. Height and peer-advertised work are not consensus authority.

## Transactions

The protocol envelope currently carries:

- `BatchTransfer`
- `QCash`

`BatchTransfer` payloads contain between `1` and `64` unique non-zero outputs.
A one-output batch transfer is the canonical single-recipient transfer form.

| Parameter | Value |
| --- | ---: |
| Maximum batch-transfer size | `24 KiB` |
| Maximum QCash transaction size | `64 KiB` |
| Maximum protocol transaction size | `64 KiB + family tag` |
| Confirmation depth | `2 blocks` |
| Local finality boundary | `5 blocks` |
| Block reward maturity | `50 blocks` |

Ordinary transaction credits and QCash redeem credits become spendable after
the confirmation depth. Block subsidy becomes spendable after the block reward
maturity.

## QCash

QCash is bearer value backed by an authenticated UTXO set.

| Parameter | Value |
| --- | ---: |
| File magic | `XPQCASH1` |
| QCash transaction version | `1` |
| Maximum withdrawal outputs | `256` |
| Maximum redeem inputs | `4` |
| Redeem eligibility delay | `1 block` |
| Redeem credit maturity | `2 blocks` |

Supported denominations are whole-XPQ amounts:

```text
1, 2, 5, 10, 20, 50, 100, 500,
1,000, 5,000, 10,000, 50,000,
100,000, 500,000, 1,000,000 XPQ
```

Withdrawing debits account value and creates QCash UTXOs. Redeeming consumes
QCash UTXOs and creates account value. Reorganizations restore account and
QCash state atomically.

## Consensus Boundary

Consensus covers network identity, frozen genesis, canonical encoding,
domain-separated hashes, address derivation, proof of work, difficulty, fork
choice, block and transaction limits, state transitions, rewards, maturities,
and authenticated account/QCash state.

Node policy such as relay fees, mempool selection, peer scoring, RPC exposure,
database layout, and snapshot transport can reject or delay local actions, but
must not make an invalid block valid.

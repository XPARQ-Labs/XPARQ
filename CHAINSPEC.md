# Paqus Chain Specification

This document records the implemented consensus identity and validation
parameters for the Paqus **Sharksphere** chain. Source code and canonical test
vectors remain authoritative when this document and an implementation differ.

## 1. Chain Identity

| Parameter | Value |
|---|---:|
| Chain name | `Paqus` |
| Patch name | `Sharksphere` |
| Chain ID | `747` |
| Protocol stage | `Mainnet` |
| Protocol version | `1` |
| Network magic | `58 50 51 01` |
| Coin | `XPQ` |
| Smallest unit | `paqus` |
| Decimal places | `8` |
| Units per XPQ | `100,000,000` |

The chain-identity commitment canonically encodes the chain name, patch name,
chain ID, coin and unit names, protocol stage/version, proof-of-work
parameters, difficulty algorithm, and network magic. It is domain-separated
with `HashDomain::ChainParams`.

## 2. Frozen Genesis

| Parameter | Value |
|---|---:|
| Height | `0` |
| Timestamp | `1700000000` |
| Nonce | `0` |
| Miner address bytes | 20 zero bytes |
| Premine | none |
| Genesis hash | `d951141d741469098219b1c3a6e3f21cf26ee7871a7d96d29c7c8fb4eae6ac7a` |

The genesis hash is frozen in the implementation. A valid canonical header
chain must begin with this exact genesis block. A different genesis identity
defines a different chain, regardless of its advertised name or chain ID.

## 3. Cryptography and Addresses

| Primitive | Definition |
|---|---|
| General hash | SHA3-256 |
| Hash length | 32 bytes |
| PoW output | Argon2id, 64 bytes |
| Transaction signature | ML-DSA-44 |
| ML-DSA public key | 1,312 bytes |
| ML-DSA secret key | 2,560 bytes |
| ML-DSA signature | 2,420 bytes |
| Address payload | 20 bytes |
| ML-DSA address text encoding | uppercase Bech32, HRP `P` |
| ML-DSA encoded address length | 40 characters |
| Reserved SQIsign Level 5 HRP | uppercase Bech32, HRP `PX` (inactive) |
| Reserved SQIsign encoded address length | 41 characters |

The default account address commits to an ordered pair of public keys:

```text
SHA3-256(
    "PAQUS_DUAL_AUTHORIZATION_V1"
    || chain_id_le_u32
    || owner_public_key
    || auth_public_key
)[12..32]
```

Changing key order changes the address. Both ML-DSA signatures are required for
outgoing Transfer, QCash, and Governance transactions.

For an unregistered account, the witness carries both public keys and both
signatures. Consensus verifies that the keys derive the sender address, then
stores the keys in account state. Once registered, the witness may use stored
key mode and carry only the two signatures.

Public keys stored in account state are not secret. Secret keys and QCash
opening secrets must never enter consensus state.

## 4. Canonical Encoding and Domains

Consensus encoding is canonical little-endian Borsh using the
`paqus-borsh-le` profile. Length-prefixed collections use their canonical Borsh
representation and are additionally bounded by semantic validation.

Signing messages bind at least:

- a transaction-family domain;
- chain ID;
- protocol version;
- frozen genesis hash;
- canonical payload bytes.

`txid` commits to the transaction family and stripped payload. `wtxid` commits
to the complete signed protocol transaction. Typed and domain-separated hashes
are used for blocks, transactions, witnesses, Merkle nodes, state,
proof-of-work, and chain parameters.

## 5. Block Header and Block Limits

The version-1 header contains, in canonical field order:

```text
version
height
previous_hash
merkle_root
witness_root
state_root
chain_commitment
miner_address
difficulty
timestamp
nonce
```

| Parameter | Value |
|---|---:|
| Block version | `1` |
| Maximum stripped block size | `5 MiB` |
| Witness scale factor | `1` |
| Maximum block weight | `5 MiB` |
| Maximum decoded protocol transactions | `4,096` |
| Maximum decoded witness keys | `8,192` |
| Maximum genesis allocations | `4,096` |

Witness scale factor 1 means witness bytes receive no consensus weight
discount. Weight and serialized virtual size are therefore equivalent under
the current rules.

Blocks contain one ordered list of signed protocol transactions. Transfer,
QCash, and Governance transactions share the same account nonce lane and
execute in committed list order.

## 6. Proof of Work

| Parameter | Value |
|---|---:|
| Algorithm | Argon2id |
| Domain salt | `PAQUS_POW_ARGON2ID_V1` |
| Memory cost | `65,536 KiB` (64 MiB) |
| Iterations | `1` |
| Lanes | `1` |
| Target block interval | `300 seconds` |
| Minimum/start difficulty | `1` |
| Adjustment interval | every block |
| Algorithm identifier | `asert-bits-v2` |
| ASERT half-life | `3,600 seconds` |
| Maximum future timestamp | `120 seconds` |
| Median-time-past window | `11` headers |

For every non-genesis header, validation checks:

1. header version and height;
2. previous-header linkage;
3. chain commitment;
4. timestamp against median time past and future-time limit;
5. expected ASERT difficulty;
6. Argon2id proof of work against that difficulty.

Fork choice selects the valid branch with the greatest cumulative work.
Height, peer count, and a peer-advertised work value are not substitutes for
locally verified chainwork.

## 7. Monetary Policy

| Parameter | Value |
|---|---:|
| Initial block subsidy | `50 XPQ` |
| Blocks per day | `288` |
| Blocks per 365-day year | `105,120` |
| Initial subsidy duration | `4 years` |
| Tail-emission start height | `420,480` |
| Tail emission per block | `1.61172119 XPQ` |
| Genesis premine | `0 XPQ` |

For height `h`:

```text
subsidy(h) =
    50 XPQ          when h < 420,480
    1.61172119 XPQ  when h >= 420,480
```

A non-genesis block must contain the exact coinbase subsidy and the sum of its
included transaction fees. Fee amounts are consensus data. Relay fee,
mempool-market fee, and miner selection thresholds expressed in `paqus/vByte`
are local node policy.

## 8. Transaction Families

The unified protocol envelope has three families:

1. `Transfer`
2. `QCash`
3. `Governance`

All families commit to:

- a versioned payload;
- signer address;
- fee;
- account nonce;
- signed timestamp metadata;
- block-height validity window;
- optional governance credential uses;
- dual-authorization witness.

The maximum ordinary signed Transfer size is 24 KiB. The bounded QCash
envelope is at most 64 KiB; the unified envelope limit includes its family tag
and the ordinary transaction bound used by the implementation.

Timestamps inside Transfer payloads are signed metadata. Consensus validity is
bounded by `valid_from` and `valid_until` block heights.

## 9. Transfer Rules

A Transfer contains one vector of outputs:

```text
TransferOutput {
    to: Address,
    amount: Amount,
}
```

| Parameter | Value |
|---|---:|
| Transaction version | `1` |
| Minimum outputs | `1` |
| Maximum outputs | `64` |

Validation rejects:

- an empty output vector;
- more than 64 outputs;
- zero-value outputs;
- sender-as-recipient outputs;
- duplicate recipient addresses;
- output-sum overflow;
- invalid nonce, fee, authorization, credentials, or validity window;
- spending more mature unlocked value than available.

There is no separate single-transfer consensus type. One output is the
canonical single-recipient transaction.

Receiving value does not require an existing account or registered public
keys. The ledger may create or credit the recipient account by address.
Authorization is required when that account later spends.

## 10. Confirmation, Maturity, and Reorganization

| Parameter | Value |
|---|---:|
| Confirmation depth | `2` |
| Finality depth | `5` |
| Block reward maturity | `50` |

For a transaction included at height `H`:

```text
H       Included
H + 2   Confirmed
H + 5   Finalized
```

Ordinary transaction credits, QCash deposit credits, and coinbase fee credits
become spendable at `H + 2`. Block-subsidy credits become spendable at
`H + 50`.

A competing greatest-work branch may reorganize non-finalized history. The
implementation rejects a reorganization crossing the local finalized
boundary. Rollback is atomic and restores account state, nonces, credits,
locks, governance state, and QCash UTXOs to their canonical pre-branch values.

These shallow 2/5 values are current development parameters.

## 11. QCash

QCash is a bearer UTXO representation of XPQ, separate from account balances.
Economic supply is the sum of account value and active QCash UTXO value.
Withdrawal debits account value while creating UTXOs; deposit consumes UTXOs
while creating account value.

| Parameter | Value |
|---|---:|
| QCash transaction version | `1` |
| File magic | `XPQCASH1` |
| File version | `1` |
| Maximum file size | `1,024 bytes` |
| Maximum withdrawal outputs | `256` |
| Maximum deposit inputs | `4` |
| Deposit eligibility delay after withdrawal | `1 block` |
| Deposited account-credit maturity | `2 blocks` |

Supported whole-XPQ denominations are:

```text
1, 2, 5, 10, 20, 50, 100, 500,
1,000, 5,000, 10,000, 50,000,
100,000, 500,000, 1,000,000 XPQ
```

Each withdrawal output commits to a coin index, denomination, and a 32-byte
commitment to wallet-held secret material. The portable file contains:

```text
version
coin_id[32]
denomination
opening_secret[32]
```

For a withdrawal included at height `W`, its QCash UTXOs are active bearer
coins immediately but may only appear in a deposit at height `W + 1` or later.
For a deposit included at height `D`, the consumed UTXOs are removed
immediately and the recipient’s account credit becomes spendable at `D + 2`.

If either transaction is removed by an allowed reorganization, canonical
rollback removes or restores the corresponding QCash state. A holder should
therefore treat recently withdrawn bearer files as reorg-sensitive until their
origin reaches the desired confirmation depth.

## 12. State Commitments and Proofs

Account state and QCash UTXO state use separate authenticated,
domain-separated commitments. The block header’s protocol state root combines
their roots. A valid block must commit to the exact post-execution state.

The implementation supports:

- account membership proofs;
- account non-membership proofs;
- QCash UTXO proofs;
- canonical header-chain proof bundles;
- trusted checkpoint plus header-extension verification.

A proof anchored at a trusted checkpoint must bind to that checkpoint’s height,
header hash, chainwork context, and required ASERT/median-time context. Proof
verification does not authorize a peer to choose the checkpoint; the verifier
must first establish the checkpoint from valid proof of work.

## 13. Authenticated Snapshots and Fast Sync

An authenticated fast-sync client:

1. obtains candidate header chains;
2. verifies each chain from the frozen genesis;
3. rejects invalid linkage, timestamps, difficulty, or PoW;
4. selects the valid chain with greatest cumulative work;
5. requests the snapshot for the selected tip;
6. verifies artifact bounds and content hash;
7. verifies the snapshot’s height, block hash, and complete protocol state
   commitment against the authenticated checkpoint;
8. writes into a staging database and activates it atomically only after all
   validation succeeds.

Snapshot chunks may be transport-compressed. Decompression is length-bounded
and does not affect canonical snapshot bytes or their content hash.

This removes trust in the snapshot provider for state correctness. It does not
remove network-isolation risk: a client connected only to an attacker can be
shown a valid but lower-work view. Operators should use multiple independently
controlled peers and network paths.

## 14. Consensus and Policy Boundary

Consensus rules include:

- frozen genesis and chain identity;
- canonical encodings and hash/signature domains;
- block and transaction structure limits;
- proof of work, difficulty, timestamps, and fork choice;
- state-transition, nonce, balance, QCash, governance, maturity, and reorg
  rules;
- exact block subsidy and included fees.

Local node policy includes:

- minimum relay fee rate;
- dynamic mempool market fee;
- miner minimum fee rate;
- mempool expiry;
- peer scoring and connection selection;
- Erlay-style reconciliation scheduling;
- compact-block reconstruction strategy;
- RPC exposure;
- snapshot chunk compression choice.

Policy may reject or delay a transaction locally but must never make an
otherwise invalid block valid.

## 15. Compatibility Rules

The numeric protocol version is only one compatibility signal. Any of the
following can change canonical identity or consensus behavior:

- structure field order or enum variants;
- canonical serialization;
- hash/signature domain strings;
- address derivation;
- genesis or chain parameters;
- PoW or ASERT arithmetic;
- block/transaction limits;
- monetary, maturity, QCash, governance, state-root, or reorg rules.

Such changes require coordinated protocol treatment and updated canonical
vectors. Existing databases must not be silently interpreted under incompatible
rules. Database format versioning itself is an implementation concern and is
not specified here.

## 16. Governance Credential Files

Governance credential files are wallet-side secret containers and are not
consensus objects. The current container has:

| Parameter | Value |
|---|---:|
| Magic | `PGD1` |
| Container version | `1` |
| Maximum encoded size | `16 KiB` |
| Password KDF | Argon2id, 64 MiB, 3 iterations, 1 lane |
| Encryption | XChaCha20-Poly1305 |
| Salt | 16 random bytes |
| Nonce | 24 random bytes |

Authenticated associated data binds the magic, container version, chain ID,
frozen genesis hash, salt, and nonce. The encrypted payload contains the
issuer-signed credential and its matching credential secret key. Decoding
checks the container version, chain identity, AEAD tag, credential signature,
and secret/public-key correspondence.

Secret-bearing Rust types redact their secret fields from `Debug`. Unencrypted
legacy Borsh credential files are deliberately rejected.

Every `GovernanceCredentialUse` signature commits to its context, nullifier,
and authorized signer address. A credential proof copied from the mempool
cannot be reassigned to a different transaction signer.

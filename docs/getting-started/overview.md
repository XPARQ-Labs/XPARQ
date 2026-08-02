# What is Paqus?

Paqus is a proof-of-work blockchain protocol with post-quantum account
authorization, deterministic state transitions, authenticated state proofs,
and a bearer-value system called QCash.

The software is split into three parts:

| Component | Purpose |
| --- | --- |
| `paqus` | Consensus types, cryptography, encoding, validation, ledger rules, and proofs |
| `paqus-node` | P2P networking, LMDB storage, mining, mempool, RPC, and synchronization |
| `wallet-cli` | Key and wallet management, transaction signing, node queries, and QCash |

## Accounts and authorization

Mainnet accounts use ML-DSA-44. An account address is derived from an ordered
owner/authorization public-key pair, and outgoing transactions require both
signatures.

An address can receive XPQ before its public keys are registered in state. On
the first spend, the transaction carries the public keys; later transactions
can use the keys stored in authenticated account state.

## Account statements

Each account has a canonical AccountStatement. It is the sender-side causal
anchor for outgoing actions. A transaction must extend the current canonical
statement for its signer.

Incoming transfers update the receiver balance but do not advance the receiver
statement. The statement is a last-signed snapshot, not a live balance mirror.

## Transactions

Paqus supports two native transaction families:

* BatchTransfer
* QCash

A transfer can contain between 1 and 64 unique recipients and is applied
atomically.

## Chain selection

Nodes validate proof of work locally and select the valid branch with the
greatest cumulative chainwork. Height or a peer-advertised work value is not a
substitute for verified chainwork.

## Transaction lifecycle

For a transaction included at height `H`:

| Height | State |
| --- | --- |
| `H` | Included and reorganization-sensitive |
| `H + 2` | Confirmed |
| `H + 5` | Beyond the local finality boundary |

Coinbase subsidy becomes spendable after 50 blocks.

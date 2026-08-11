# XPARQ Whitepaper

## Proof of Work, Post-Quantum Dual Authorization, and QCash Bearer Value

**Document status:** technical description of the active implementation and its security boundaries

**Reference implementation:** XPARQ Sharksphere, protocol format `1`

**Software version at publication:** `0.2.11`

**Date:** August 10, 2026

> This document describes the protocol that can be verified from the current
> XPARQ implementation. Ideas that are not yet consensus rules are explicitly
> identified as future work. This document is not a promise of returns, an
> investment prospectus, or a substitute for an independent security audit.

## Abstract

XPARQ is a proof-of-work blockchain protocol designed around deterministic
execution, post-quantum transaction authorization, independently verifiable
state commitments, and transferable value through QCash bearer files.

XPQ uses an owned-UTXO model. An address does not store a balance; its balance
is derived from all unspent XPQ outputs owned by that address. Every address is
bound to two keys with distinct roles—an `owner` key and an `authorization`
key—and outgoing transactions require both signatures by default.

Blocks are secured by Argon2id proof of work. The canonical chain is selected
by the greatest validated cumulative work, not by block height or peer claims.
XPARQ uses Weight-Based Difficulty Adjustment (WBDA): difficulty and block
subsidy are evaluated every 2,048 blocks from canonical block-weight
utilization.

QCash provides a bearer representation of XPQ. A withdrawal consumes owned
XPQ UTXOs and creates QCash UTXOs whose opening secrets are stored in `.QCash`
files. Redemption consumes those QCash UTXOs and creates new owned XPQ UTXOs.
QCash does not create new supply and is not presented as an anonymous,
shielded, or zero-knowledge transaction system.

## 1. Goals and Design Principles

XPARQ is built around five primary principles:

1. **Consensus determinism.** Nodes processing the same canonical input must
   produce the same validation decisions, state, and state root.
2. **Verification instead of peer trust.** Data obtained from peers, snapshot
   providers, and bootstrap nodes must be proven against proof of work and
   protocol commitments.
3. **Layered authorization.** Account ownership and operational authorization
   are separated into two keys that are both required to spend value.
4. **Value conservation across representations.** XPQ may exist as an owned
   XPQ UTXO or an active QCash UTXO, but it must never be counted in both at
   once.
5. **Explicit claim boundaries.** Local finality is not BFT finality, QCash is
   not on-chain privacy, and sidechain designs are not part of active
   consensus.

## 2. Network Identity and Parameters

| Parameter | Mainnet | Testnet | Devnet |
| --- | ---: | ---: | ---: |
| Asset name | XPQ | tXPQ | dXPQ |
| Chain ID | 747 | 717 | 707 |
| Network magic | `XPQ\x01` | `TXPQ` | `DXPQ` |
| Protocol format | 1 | 1 | 1 |
| Active signature scheme | ML-DSA-44 | ML-DSA-44 | Experimental SQIsign Level 5 |
| Genesis | Frozen hash | Runtime-derived | Runtime-derived |

The smallest unit is `paqs`:

```text
1 XPQ = 1,000,000 paqs
decimals = 6
```

Mainnet launched without a premine. Every mainnet XPQ created after genesis
must originate from a block subsidy validated by consensus.

The active protocol format remains `1`. Software package versions may change
without changing the consensus-format identifier. Conversely, a change to a
canonical structure, field order, hash domain, genesis identity, proof of work,
WBDA, state root, or validation rule may be consensus-breaking even when its
version field remains `1`.

## 3. Protocol Architecture

The XPARQ implementation is divided into three application layers:

```text
wallet
  |  constructs and signs transactions
  v
node
  |  RPC, mempool, P2P, mining, database, snapshots
  v
core
     encoding, cryptography, blocks, consensus, state, ledger
```

`core` is the source of consensus rules. The node owns operational policy such
as mempool retention, connectivity, and RPC transport. The wallet owns
mnemonics, key material, transaction construction, proof checkpoints, and
bearer files. Node policy is not a consensus rule unless it is explicitly
committed to and validated by core.

## 4. Encoding, Hashing, and Commitments

Consensus objects use canonical little-endian Borsh encoding. Primary hashes
use SHA3-256 with domain separation, preventing identical bytes in distinct
contexts—such as transactions, coin identifiers, state, or QCash files—from
being interpreted as the same object.

A block header commits to:

- the block version;
- the parent hash;
- the ordered transaction Merkle root;
- the protocol state root after block execution;
- the claimed difficulty;
- the canonical serialized block weight;
- the proof-of-work nonce.

Block height is validated from its position relative to the parent but is not
part of the header hash. The maximum block size and weight are both 5 MiB. WBDA
weight is the complete canonical serialized size, not a local estimate.

The protocol state root combines three authenticated state roots:

```text
protocol_state_root = H_domain(
    account_state_root,
    xpq_state_root,
    qcash_state_root
)
```

This commitment binds authorization accounts, owned XPQ UTXOs, and active
QCash UTXOs to the chain header.

## 5. Proof of Work and Fork Choice

XPARQ uses Argon2id as its proof-of-work function with the following
parameters:

| Parameter | Value |
| --- | ---: |
| Memory | 64 MiB |
| Iterations | 1 |
| Lanes | 2 |
| PoW output | 64 bytes |
| Salt/domain | `XPARQ_POW_ARGON2ID_V1` |

Every non-genesis block must declare the correct difficulty and produce valid
proof of work at that difficulty. Per-block work is derived from difficulty
and accumulated in a 512-bit value. Fork choice selects the tip with the
greatest cumulative work. Bootstrap peers and seed nodes therefore provide
connectivity; they do not have authority to choose the chain.

If two tips have equal cumulative work, the implementation selects the lower
tip hash as a deterministic tie-breaker.

### 5.1 Weight-Based Difficulty Adjustment

Difficulty is evaluated in epochs of 2,048 blocks. Utilization is calculated
as:

```text
utilization = average canonical block weight / 5 MiB
            = total epoch block weight / (2,048 x 5 MiB)
            = total epoch block weight / 10 GiB
```

The adjustment rules are:

| Completed-epoch utilization | Next-epoch difficulty | Next-epoch subsidy |
| --- | ---: | ---: |
| Below 30% | +1 | +1 XPQ |
| 30% through 70%, inclusive | unchanged | unchanged |
| Above 70% | -1 | -1 XPQ |

Minimum difficulty is `1`. XPARQ does not use block timestamps as a target
interval in this WBDA formula; the active mechanism responds to block-weight
utilization. WBDA must therefore not be described as guaranteeing a fixed
block interval or as fully preventing miners from influencing utilization.

## 6. XPQ Economics and Issuance

The initial subsidy is 10 XPQ per block. After each completed epoch, the
subsidy moves in the same direction as WBDA and is constrained as follows:

```text
minimum subsidy = 1 XPQ per block
base subsidy    = 10 XPQ per block
maximum subsidy = 20 XPQ per block
step            = 1 XPQ per epoch
maturity        = 50 blocks
```

Only the subsidy valid for the current epoch is issued. If the subsidy falls
from 10 XPQ to 9 XPQ, the one-XPQ difference is never created; it is not burned
after issuance and is not assigned to a treasury. If the subsidy later rises,
the additional issuance applies only to new blocks.

The active XPARQ implementation has no fixed hard supply cap. Total supply
depends on the number of blocks and the adaptive subsidy path, subject to the
per-block range of 1–20 XPQ. Mainnet genesis contains no allocation to a
founder, foundation, developer, treasury, or any other party.

### 6.1 Miner Payments

Core has no separate `fee` field. A miner payment is represented as an ordinary
output targeting `BlockMiner`. A typical transfer is:

```text
XPQ inputs -> recipient output + change output + optional BlockMiner output
```

Consensus validates value conservation, not a minimum price for block
inclusion. Nodes and miners may prioritize transactions through local policy,
but a transaction without a miner payment is not automatically invalid in
core.

## 7. Owned XPQ UTXOs

An address balance is the sum of its mature, unspent owned XPQ outputs. A
transfer explicitly names input coins and creates new outputs for the
recipient, change, and—when used—the miner.

```text
XpqCoinId = H_domain(transaction_hash, output_index)
```

Old inputs are removed atomically, and every output receives a deterministic
new coin identifier. Replay and double-spend protection follow from the rule
that each coin may be consumed only once. Accounts do not store a transaction
nonce or a separate balance field.

## 8. Addresses and Dual Authorization

An XPARQ address is derived from an ordered pair of public keys. Conceptually:

```text
address = last_20_bytes(SHA3-256(
    active_signature_domain || chain_id_le || owner_pk || authorization_pk
))
```

The canonical text representation is lowercase Bech32 with the `x` human-
readable prefix. Key order matters: exchanging the owner and authorization
roles produces a different identity.

Both signatures are required by default:

- the **owner key** proves primary ownership;
- the **authorization key** provides a second approval layer.

The first outgoing transaction carries both public keys. After successful
validation, the ledger stores the pair in authenticated account state. Later
transactions carry only two signatures, while the node obtains both public
keys from state. An address may receive XPQ before its authorization keys have
been registered.

Mainnet and testnet use ML-DSA-44. SQIsign Level 5 is available as an
experimental blockchain-test backend on devnet and is not an active mainnet
consensus scheme.

The current wallet derives its owner key from a mnemonic and its authorization
key from a password using Argon2id derivation. Hardware-wallet integration,
address-preserving authorization-key rotation, and specialized recovery
policies are not active consensus features.

## 9. QCash

QCash moves XPQ between two UTXO sets committed by protocol state:

```text
owned XPQ UTXO --withdraw--> active QCash UTXO
active QCash UTXO --redeem--> owned XPQ UTXO
```

### 9.1 Withdrawal

A withdrawal consumes owned XPQ inputs and creates one or more QCash UTXOs in
canonical whole-XPQ denominations. Available denominations range from 1 XPQ to
1,000,000 XPQ. Fractional XPQ cannot become QCash; any remainder stays in an
owned XPQ change output.

For every coin, the ledger stores its coin identifier, denomination, and a
commitment to the redeem key. The opening secret is not stored by the ledger.
The wallet writes it to a bearer file with a name such as:

```text
100XPQ_<FULL_COIN_ID>.QCash
```

The file contains format version `1`, an opaque 32-byte coin identifier, its
denomination, and a 32-byte `redeem_secret`. Anyone who obtains a valid,
unredeemed file can use it. The file must be protected like physical cash.

### 9.2 Redemption

QCash created at height `H` becomes redeemable at `H + 1`. A successful redeem
immediately consumes the QCash UTXO and creates:

- exactly one address-recipient output; and
- at most one `BlockMiner` output.

Their sum must equal the gross QCash value. A redemption miner payment is
therefore a division of the bearer denomination, not newly created value.
Owned XPQ produced by redemption becomes spendable after the normal
confirmation depth.

### 9.3 QCash Properties and Boundaries

QCash provides bearer portability and separates its opening secret from the
ledger, but it is not an on-chain privacy system. Coin identifiers, withdrawal
state, and public redemption proofs remain protocol data. The active design
does not claim a zero-knowledge proof system, shielded pool, privacy nullifier,
or guaranteed unlinkability.

Only the bearer object's `redeem_secret` is zeroized when released from memory.
The coin identifier is a public lookup and replay-protection identifier, not a
secret or privacy nullifier.

## 10. Atomic Execution, Confirmation, and Reorganization

Transactions and blocks are applied atomically. Failed validation must not
leave a partial mutation in canonical state. The ledger retains rollback
journals and checks value-conservation invariants across owned XPQ and QCash.

The lifecycle of a transaction included at height `H` is:

| Height or depth | Status |
| --- | --- |
| `H` | Included and still reorganization-sensitive |
| Depth 2 | Confirmed; transfer and redemption outputs mature |
| Depth 5 | Finalized under the local reorganization boundary |

Mining subsidies mature after 50 blocks. In XPARQ, `finalized` means that a
node rejects a reorganization crossing the five-block consensus boundary. It
is not BFT or proof-of-stake finality and does not establish irreversibility
against a majority-hashpower attack or a community-coordinated software
change.

QCash rollback follows the canonical chain. A withdrawal on a disconnected
branch is removed. A disconnected redemption restores the QCash UTXO it had
consumed. Old rollback-only data may be pruned after the finality boundary,
while explorer history can be retained separately.

## 11. Proofs, Snapshots, and Fast Sync

XPARQ supports account proofs, QCash proofs, protocol state commitments,
snapshots, and trusted checkpoints. Header-chain verification checks:

- parent linkage and genesis identity;
- expected WBDA difficulty;
- Argon2id proof of work;
- committed block weight;
- cumulative chainwork;
- snapshot binding to a checkpoint protocol state root.

A snapshot provider is a data source, not a consensus authority. A node may
activate a snapshot only when its state commitments match a verified header
checkpoint. After a wallet retains a trusted checkpoint, new proof bundles may
carry only the header extension after that checkpoint instead of repeating all
headers from genesis.

This model retains a network assumption: the verifier must obtain the actual
greatest-work chain. Comparing multiple independently operated peers reduces
eclipse risk but does not eliminate it.

## 12. Networking and Node Operations

The node uses libp2p over TCP. P2P sessions are authenticated and encrypted
with Noise, multiplexed with Yamux, and use Ping, Identify, and Kademlia for
connection lifecycle and discovery. Application payloads retain canonical
Borsh encoding under protocol ID `/xparq/borsh/1`.

The node stores an Ed25519 peer identity separate from transaction keys. A P2P
identity cannot spend XPQ and has no authority over fork choice.

Wallet HTTP RPC listens on loopback by default. The current optional gRPC
listener has no built-in TLS or authentication and must be restricted to
loopback or a trusted private network. P2P Noise encryption does not
automatically protect RPC endpoints.

## 13. Security Analysis and Model Boundaries

### 13.1 Intended Properties

- Transaction forgery requires signatures valid under authenticated account
  state.
- Spending requires both owner and authorization signatures by default.
- UTXO consumption prevents ordinary replay and double spending.
- Per-height and per-epoch subsidy validation constrains XPQ issuance.
- Snapshots must match a state root on a validated proof-of-work chain.
- Fork choice uses cumulative work rather than a peer's claimed height.
- Decoder size and item-count limits reduce resource-amplification risks.

### 13.2 Threats Not Eliminated

- majority-hashpower attacks or reorganizations before the finality boundary;
- eclipse and isolation attacks against nodes that see only malicious peers;
- malware, keyloggers, stolen mnemonics or passwords, and endpoint compromise;
- theft, copying, or earlier redemption of a `.QCash` file;
- denial of service against P2P, RPC, databases, or cryptographic verification;
- miner influence over block-weight utilization used by WBDA;
- implementation bugs, dependency weaknesses, and cryptographic weaknesses;
- metadata leakage and relationship analysis involving QCash activity;
- permanent loss caused by inadequate key or bearer-file backups.

The five-block finality depth is a local protocol rule, not economic proof that
five confirmations are sufficient for every transaction value. Users must set
their operational risk tolerance according to value and network conditions.

## 14. Upgrades and Compatibility

The crypto-agility registry can represent legacy, transition, and upgraded
phases for primitives within the same family. Registration does not mean that
an algorithm is active. An upgrade requires a nonzero authorization identifier,
a deterministic activation window, and consensus rules that have been agreed
upon and implemented.

The following changes must be treated as consensus changes or state migrations
until proven otherwise:

- canonical encoding or field order;
- domain strings and typed hashes;
- network identity or frozen genesis;
- proof of work, difficulty, WBDA, reward, maturity, or fork choice;
- account, XPQ UTXO, QCash UTXO, or protocol-state-root structure;
- committed artifact, snapshot, checkpoint, proof, or database formats.

A database created for a different network or schema must not be reused without
an explicit migration or a rebuild from canonical data.

## 15. Implementation Status and Future Direction

The repository currently includes consensus core, a full node, P2P networking,
mining, a mempool, LMDB storage, HTTP RPC, optional gRPC status, a wallet CLI,
owned XPQ UTXOs, QCash, proofs, snapshots, rollback, and fuzz targets.

The following are not part of the active mainnet protocol at the time of this
document:

- a proof-of-stake sidechain or bridge chain;
- a rollup with L1 data-availability and validity or fraud proofs;
- a general-purpose smart-contract virtual machine;
- shielded transactions or a zero-knowledge privacy pool;
- hardware-wallet dual authorization;
- address-preserving authorization-key rotation;
- SQIsign as the mainnet consensus signature scheme.

PoS research should be described as a **sidechain or bridge chain** until L1
actually verifies checkpoints, data availability, and adequate exit rules. If
implemented, its minimum economic invariant is that total L2 XPQ claims must
never exceed finalized XPQ locked in the L1 bridge escrow.

## 16. Active Consensus Parameters

| Parameter | Value |
| --- | --- |
| Mainnet chain ID | 747 |
| Protocol format | 1 |
| Unit | 1 XPQ = 1,000,000 paqs |
| Mainnet/testnet signature | ML-DSA-44 dual authorization |
| Devnet signature | Experimental SQIsign Level 5 |
| Hash | Domain-separated SHA3-256 |
| PoW | Argon2id, 64 MiB, 1 iteration, 2 lanes |
| Fork choice | Greatest validated cumulative work |
| Maximum block size and weight | 5 MiB |
| WBDA epoch | 2,048 blocks |
| Neutral WBDA zone | 30%–70%, inclusive |
| Minimum difficulty | 1 |
| Initial subsidy | 10 XPQ per block |
| Subsidy range | 1–20 XPQ per block |
| Mainnet premine | None |
| Hard supply cap | None |
| Confirmation depth | 2 blocks |
| Finality boundary | 5 blocks |
| Mining-reward maturity | 50 blocks |
| QCash redemption delay | 1 block |
| Active transaction, QCash, and artifact formats | 1 |

## 17. Conclusion

XPARQ combines Argon2id proof of work, cumulative-work fork choice,
post-quantum dual authorization, authenticated state commitments, and two UTXO
representations to provide XPQ that can be directly owned or transferred as
QCash bearer value.

The design depends on clear boundaries: consensus core determines validity,
the node applies operational policy, the wallet protects keys and bearer
secrets, and proofs bind external data to a verified chain. Its security still
depends on hashpower distribution, peer diversity, endpoint protection, secure
handling of keys and `.QCash` files, implementation quality, and continuous
independent review.

## Implementation References

- [`README.md`](README.md) — active protocol overview and parameters.
- [`core/src/consensus`](core/src/consensus) — PoW, WBDA, difficulty, and subsidy.
- [`core/src/genesis`](core/src/genesis) — network identity and frozen genesis.
- [`core/src/transaction`](core/src/transaction) — transfer and QCash envelopes.
- [`core/src/state`](core/src/state) — accounts, XPQ UTXOs, QCash UTXOs, and roots.
- [`core/src/ledger`](core/src/ledger) — execution, fork choice, rollback, and proofs.
- [`core/src/qcash`](core/src/qcash) — bearer files and QCash domain logic.
- [`node`](node) — networking, RPC, mining, storage, and snapshot transport.
- [`wallet`](wallet) — key management, transactions, proofs, and QCash workflows.

---

Copyright (c) 2026 XPARQ contributors. This document follows the repository
license unless stated otherwise.

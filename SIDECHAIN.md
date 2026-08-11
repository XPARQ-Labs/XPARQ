# XPARQ Proof-of-Stake Sidechain

Status: experimental scaffold. This directory does not implement a live bridge,
complete proof-of-stake protocol, or trust-minimized rollup.

## Workspace boundary

The sidechain lives in [`sidechain/`](sidechain) as an independent Cargo
workspace. It is explicitly excluded from the root XPARQ workspace, has its
own `Cargo.lock`, and must be built from its own directory:

```bash
cd sidechain
cargo check --workspace --locked
cargo test --workspace --locked
```

The scaffold contains:

- `xparq-sidechain-primitives`: FIPS 202 SHA3-256, SQIsign Level 5
  wire types and verification, domain-separated hashes, and dual-key addresses;
- `xparq-sidechain-consensus`: chain parameters, validator records, block
  proposals, quorum votes, and validator-set commitment helpers;
- `xparq-sidechain-wxpq`: finalized L1 deposit boundary, replay-safe wXPQ mint,
  balances and transfers, burn-before-release withdrawal intents, and permanent
  token-issuance burn accounting;
- `xparq-sidechain-tokens`: fixed-supply user-token creation funded by wXPQ
  burns, token balances, transfers, and an authenticated registry state root;
- `xparq-sidechain-native-token-program`: fixed, VM-free execution of native
  token instructions with dual SQIsign authorization, account nonces, atomic
  state transitions, and canonical receipts.

## Cryptographic profile

| Function | Active sidechain choice |
| --- | --- |
| Hashing | SHA3-256, FIPS 202, matching XPARQ L1 |
| Signatures | SQIsign Level 5 |
| Address size | 20 bytes |
| Address text encoding | lowercase Bech32, HRP `x` |
| Authorization structure | ordered owner and authorization public keys |
| Active format identifiers | `1` |

The address *structure* matches XPARQ L1: it is a 20-byte dual-authorization
address encoded as lowercase `x1...` Bech32. Its value is deliberately derived
with a sidechain-specific SHA3 domain and a caller-supplied sidechain chain ID.
It is therefore not assumed to equal the L1 address produced from the same key pair.
Treating sidechain and L1 addresses as interchangeable would be unsafe.

SQIsign is an experimental candidate implementation in this repository. The
scaffold does not claim standardization, production readiness, or independent
audit coverage.

SHA3-256 is used for sidechain-owned consensus identifiers and signing
roots. SQIsign's internal transcript and challenge hashing remain part of the
SQIsign algorithm and are not replaced with the protocol hash; changing those
internals would create a different, incompatible signature scheme.

## Consensus scope

The current consensus crate defines canonical data boundaries without choosing
undeclared economic parameters. A caller must explicitly provide the chain ID,
epoch length, quorum numerator and denominator, minimum validator stake, and
maximum validator count. The scaffold validates these parameters and supports
deterministic validator-set roots and vote signing roots.

## wXPQ accounting

wXPQ uses six decimals and is measured in the same `paqs` unit as XPQ:

```text
1 wXPQ = 1,000,000 paqs
```

The accounting invariant is:

```text
total wXPQ supply + pending burned withdrawals + token-issuance burns
    == finalized XPQ still locked in the L1 bridge escrow
```

A deposit claim cannot reach the mint method until a caller-supplied
`FinalizedL1DepositVerifier` accepts its L1 proof. Deposit IDs are consumed once
to prevent replay and commit to both the L1 and sidechain chain identities. A
withdrawal burns wXPQ first and records a pending intent;
the scaffold does not yet release L1 XPQ or reduce the recorded L1 backing.
The complete wXPQ ledger has a domain-separated SHA3-256 state root covering
balances, consumed deposits, pending withdrawals, supply, and backing totals.

## User-token creation

The sidechain is intended to provide transferable assets for user-created token
markets. Its initial creation rate is fixed at:

```text
burn 1 wXPQ (1,000,000 paqs) -> issue 100,000,000 token units
```

Token creation accepts only positive whole-wXPQ multiples. User tokens use zero
decimal places in this initial format, and their entire immutable supply is
assigned to the creator in the creation transition. There is no subsequent
mint or administrator-mint path.

The wXPQ burn and token creation are one atomic state transition: either both
ledgers commit, or neither changes. Exactly one immutable issuance event is
stored for each Token ID, and its burn commitment is that Token ID's SHA3-256 hash.
The same burn commitment cannot be consumed twice, and no later event can add
supply to an existing Token ID. A new burn creates a new Token ID rather than
increasing an old token's supply.

A token ID commits to the protocol version, sidechain chain ID, creator address,
creator nonce, metadata, and burn amount through domain-separated SHA3-256.
Symbols are display metadata and are not globally unique; applications must
identify assets by Token ID.

Burning wXPQ permanently destroys the holder's corresponding withdrawal claim.
The scaffold continues to account for that XPQ as locked L1 backing, but it
does not yet define any mechanism for releasing, spending, or governing the L1
XPQ associated with token-issuance burns.

The current token crate is an asset and transfer foundation. It does not yet
implement an order book, AMM, liquidity pools, trading fees, or transaction
execution integration.

## Native token program without a VM

Token execution does not require a smart-contract VM. Every node recognizes a
fixed, chain-scoped Native Token Program ID and deterministically executes the
same version-1 instruction enum. The initial instruction set is `CreateToken`
and `Transfer`; arbitrary bytecode and contract deployment are not accepted.

Each transaction commits to the chain ID, sender, account nonce, and complete
instruction through domain-separated SHA3-256. Both ordered SQIsign Level
5 keys must sign that root, and the keys must derive the sender's sidechain
address. Successful execution increments the sender nonce and emits a canonical
receipt. Failed execution commits no program state.

Under this model the 32-byte Token ID is the native asset address beneath the
fixed Native Token Program ID. It is not an executable contract address. This
keeps token transfers deterministic and small while leaving a general-purpose
VM as an independent future design choice.

The verifier trait is a trust boundary, not a verifier implementation. Until
XPARQ L1 exposes an authenticated escrow transition and the sidechain verifies
L1 finality plus inclusion proofs, wXPQ is accounting infrastructure rather
than an operational trust-minimized bridge.

Still required before a network can launch:

- validator-set transition and staking state machine;
- leader selection and randomness;
- fork choice, finality proof aggregation, and equivocation evidence;
- slashing, unbonding, reward, and liveness rules;
- transaction execution and authenticated state;
- P2P, mempool, storage, RPC, wallet, genesis, and upgrade procedures;
- an L1 escrow consensus transition plus real deposit and release proof
  verification;
- independent cryptographic, consensus, and bridge audits.

Until those components exist, this is a sidechain foundation—not a deployed
bridge chain and not a rollup.

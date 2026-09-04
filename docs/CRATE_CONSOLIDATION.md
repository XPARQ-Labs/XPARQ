# Crate Consolidation and Repository History

## Recommendation

XPARQ should remain a Cargo workspace, but the protocol crates should eventually
be consolidated into one library crate. A practical target is five packages:

| Package | Responsibility |
| --- | --- |
| `xparq` | Canonical protocol types, coin and asset primitives, transactions, blocks, consensus, ledger, and genesis |
| `xparq-crypto` | Cryptographic implementations, signature profiles, addresses, hashing, and Argon2id proof of work |
| `xparq-extension` | WASM execution and its explicitly bounded host interface |
| `xparq-node` | Storage, networking, RPC, mempool, and mining application |
| `xparq-wallet` | Wallet library and wallet application |

The current `common`, `coin`, `asset`, `transaction`, `blockchain`, `consensus`,
`ledger`, `genesis`, and `xparq` crates form one tightly coupled protocol unit.
They use the same release version, change together when canonical encoding or
consensus changes, and are not useful as independently deployed products. They
are the strongest candidates to become modules of the single `xparq` library.

Keep `xparq-crypto` separate initially. It has a distinct audit surface, heavy
feature-controlled implementations, and locally vendored cryptographic
dependencies. It can be merged later, but doing so provides less immediate
value than consolidating the protocol graph.

Keep `xparq-extension` separate because WASM execution is a useful trust and
dependency boundary. The small `extension/bridge` package should become an
`extension::bridge` module unless it is intended for independent publication.

Keep the node and wallet separate from the protocol library. They have
different security roles and dependency sets: the node owns networking and
storage, while the wallet owns secret material and transaction construction.
The `depend/` directory is vendored source and must remain outside the product
workspace packages.

## Why not one package for everything?

Cargo can build a library plus `node` and `wallet` binaries from one package,
so a literal single-package repository is possible. It would, however, unify
wallet, server, database, networking, WASM, and cryptographic dependencies into
one feature graph. That increases build coupling and makes trust boundaries
less visible. One protocol crate inside a small workspace is the simpler and
safer result.

## Proposed module layout

```text
xparq/src/
├── common/
├── crypto-facing APIs
├── coin/
├── asset/
├── transaction/
├── blockchain/
├── consensus/
├── ledger/
├── genesis/
└── lib.rs
```

Module boundaries should remain explicit even after package boundaries are
removed. In particular, the ledger applies consensus-approved transitions;
consensus must not depend on ledger storage; and application crates must use
the public `xparq` API rather than internal file paths.

## Migration sequence

1. Normalize package metadata and keep the current workspace green.
2. Move `common`, `coin`, and `asset` into `xparq` modules and preserve their
   public re-exports.
3. Move transaction and blockchain types, then consensus, ledger, and genesis.
4. Replace inter-package dependencies with `crate::` module paths one layer at
   a time.
5. Merge `extension/bridge` into `xparq-extension` if it has no external users.
6. Remove old package directories and workspace dependency aliases only after
   all consumers compile against the consolidated API.

Canonical Borsh encodings, hash domains, identifiers, genesis identity, and
consensus results must not change merely because Rust modules move. Each phase
should pass workspace checks, affected tests, serialization fixtures, genesis
tests, ledger apply/rollback tests, reorg tests, and node/wallet integration
tests. A deliberate encoding change requires an explicit chain reset or state
migration decision.

## New repository versus old history

The configured remote is `XPARQ-Labs/XPARQ-2`, and package metadata should use
that same URL. Pushing an existing branch to a new GitHub repository preserves
its commit ancestry by design. The old commits are history, not a reference to
the old remote.

The recommended policy is to keep that history and clean only active manifests,
documentation, examples, and generated API descriptions. Historical changelog
entries may continue to mention features or layouts that existed in old
releases, provided they are clearly historical.

If a repository with no previous ancestry is truly required, create a new root
commit (or filter the history) and force-push it. Both operations replace commit
IDs and disrupt existing clones, forks, links, and tags. They must be performed
only as a separately approved repository migration with a backup and an agreed
cutover plan; this cleanup does not rewrite Git history.

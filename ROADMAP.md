# XPARQ Core Crate Decomposition Roadmap

Status: proposal. This document describes an architectural migration; it does
not change consensus behavior or claim that the crates below already exist.

## Objective

Convert the current `core` package into a set of domain-focused crates with an
acyclic dependency graph. One domain should have one clear owner. The existing
`xparq` package remains as a compatibility facade while node, wallet, fuzzing,
and external consumers migrate to the new crates.

The decomposition must:

- preserve all canonical bytes, hashes, state roots, genesis identities, and
  validation results;
- keep active protocol, storage, artifact, transaction, QCash, and proof format
  identifiers at `1` unless a separate consensus upgrade explicitly changes
  them;
- preserve the current mainnet, testnet, and devnet feature boundaries;
- prevent circular crate dependencies and duplicate definitions of canonical
  types;
- keep consensus-critical APIs narrow and make state mutation available only
  through validated transitions;
- allow each extracted crate to be tested and fuzzed independently.

This is not a cryptographic upgrade, a database migration, a consensus-rule
change, or a commitment to publish every internal crate to crates.io.

## Why direct module-to-crate moves will not work

The current modules have several cross-layer dependencies:

- `block` owns `BlockHeight`, but transaction, state, consensus, authenticated
  header sync, and ledger all need it;
- `consensus::supply` owns `Amount`, although QCash, transaction, state, block,
  and wallet-facing APIs use it;
- `transaction::qcash` depends on ordinary transaction output types and XPQ
  coin identifiers, while the unified transaction envelope contains QCash;
- QCash state currently lives under `state::utxo`, not under `qcash`;
- the shared `codec` and `error` modules import types from most other modules;
- block, state, genesis, ledger, and proof code currently know details from
  neighboring layers.

Those edges must be reversed or reduced inside the existing package before the
files are physically extracted.

## Proposed workspace layout

```text
XPARQ/
├── Cargo.toml
├── crates/
│   ├── xparq-primitives/
│   ├── xparq-codec/
│   ├── xparq-crypto/
│   ├── xparq-tx-base/
│   ├── xparq-qcash/
│   ├── xparq-transaction/
│   ├── xparq-block/
│   ├── xparq-consensus/
│   ├── xparq-state/
│   ├── xparq-ledger/
│   ├── xparq-genesis/
│   └── xparq-sync/
├── core/                 # `xparq` compatibility facade
├── node/
├── wallet/
└── depend/               # vendored upstream packages, not workspace members
```

The final crate count may be reduced when two boundaries prove inseparable, but
cycles must not be hidden by merging unrelated high-level domains.

## Crate responsibilities

### `xparq-primitives`

Own small canonical value types used by multiple layers: `Amount`, `Height`,
typed hashes, coin and outpoint identifiers, and other data-only protocol
identifiers. It must not depend on crypto algorithms, blocks, transactions,
state, or ledger execution.

Moving a type here does not permit changing its Borsh or Serde representation.

### `xparq-codec`

Own canonical encoding helpers, bounded decoding utilities, and codec-specific
errors. Domain-specific decoders remain with their owning crate. This crate
must not become an umbrella that imports block, transaction, state, or ledger
types.

### `xparq-crypto`

Own addresses, public keys, signatures, key derivation, domain-separated
hashing, proof-of-work hashing helpers, and crypto-agility policy types. It may
depend only on primitives, codec, and cryptographic dependencies.

### `xparq-tx-base`

Own transaction components shared by ordinary transfers and QCash: validity
windows, output targets, transfer outputs, authorization proofs, signing
contexts, and common transaction errors. This small boundary prevents the
QCash crate and unified transaction crate from depending on each other.

### `xparq-qcash`

Own the complete QCash domain:

- arbitrary positive amounts in paqs and multi-file amount selection;
- bearer coin files, keys, commitments, metadata, and file bounds;
- withdraw, full/partial redeem, and split payloads and signatures;
- QCash coin identifiers, UTXO entries, authenticated proofs, and journals;
- atomic withdraw/redeem state operations;
- QCash-specific errors and regression tests.

Header-chain and authenticated checkpoint verification are deliberately
excluded and moved to `xparq-sync`, because they depend on higher-level chain
data.

### `xparq-transaction`

Own ordinary transfers and the unified signed protocol transaction envelope.
It depends on `xparq-tx-base` and `xparq-qcash`; `xparq-qcash` must never depend
back on this crate.

### `xparq-block`

Own headers, bodies, emission transactions, Merkle proofs, block sizing, and
structural validation. Heights and hashes come from primitives. Economic and
chain-selection policy belongs to consensus, not block data structures.

### `xparq-consensus`

Own proof-of-work validation, WBDA, supply and reward policy, chain work, fork
choice, finality depths, maturity rules, and network-specific consensus
parameters. It may inspect blocks but must not mutate ledger state.

### `xparq-state`

Own accounts, authorization state, XPQ UTXOs, state commitments, authenticated
account proofs, and state invariants. QCash state remains owned by
`xparq-qcash`; this crate consumes only its public state interface and roots.

Raw mutation helpers remain crate-private. Public operations must either be
validated transitions or atomic operations with rollback guarantees.

### `xparq-ledger`

Own chain execution, transaction application, rollback journals, reorg
planning, cross-domain invariants, and protocol state-root composition. It is
the main integration layer and may depend on all lower-level domain crates.

### `xparq-genesis`

Own chain parameters, genesis construction, frozen genesis checks, snapshot and
checkpoint artifacts, and trust anchors. It depends on stable block, state,
consensus, and ledger APIs rather than their internal collections.

### `xparq-sync`

Own header-chain chunks, trusted checkpoints, chain-work verification, and
authenticated synchronization procedures. Reorganization rollback remains in
the ledger/node execution layer, while QCash transaction recovery remains the
normal rollback-and-mempool-requeue path rather than a separate protocol.

### `xparq` facade (`core`)

Initially re-export the public API under the existing paths, for example
`xparq::qcash`, `xparq::transaction`, and `xparq::ledger`. Node and wallet can
then migrate one import group at a time. The facade must contain no second copy
of canonical types or consensus logic.

## Target dependency direction

Arrows below mean "depends on":

```text
xparq-primitives
├── xparq-codec
├── xparq-crypto ────────────────> codec
└── xparq-tx-base ───────────────> codec, crypto
    ├── xparq-qcash ─────────────> codec, crypto
    └── xparq-transaction ───────> qcash, codec, crypto
        └── xparq-block ─────────> codec, crypto
            └── xparq-consensus ─> crypto

xparq-state ─────────────────────> primitives, codec, crypto, tx-base, qcash
xparq-ledger ────────────────────> transaction, block, consensus, state, qcash
xparq-genesis ───────────────────> block, consensus, state, ledger
xparq-sync ──────────────────────> block, consensus, genesis, ledger
xparq facade ────────────────────> all domain crates
```

No lower-level crate may depend on `xparq`, `xparq-ledger`, node, or wallet.

## Migration phases

### Phase 0 — Freeze the behavioral baseline

- Record golden vectors for canonical block, transaction, QCash file, proof,
  snapshot, and checkpoint encodings.
- Record the frozen genesis hash and representative protocol state roots.
- Keep regression coverage for authorization address binding, stored-key
  transactions, QCash atomic journals, redeem conservation, and rollback.
- Generate a dependency report from current `crate::...` imports and classify
  each edge as data, validation, state mutation, or test-only.

Exit condition: moving code without changing bytes or validation decisions can
be detected automatically.

### Phase 1 — Untangle boundaries inside `core`

- Move `Amount`, `Height`, typed hashes, and coin identifiers into a temporary
  internal `primitives` module.
- Split shared transaction components from transfer and QCash payloads.
- Move fork-choice and chain-work policy out of ledger internals.
- Move QCash UTXO/proof ownership out of generic state internals.
- Replace the global error umbrella with errors owned by each domain and
  source-preserving integration errors.
- Replace broad codec imports with domain-owned bounded decoders.

Exit condition: the intended crate dependency graph can be represented without
a cycle while everything still compiles as one package.

### Phase 2 — Extract foundation crates

Create `xparq-primitives`, `xparq-codec`, and `xparq-crypto`. Re-export them
through `xparq` and migrate fuzz targets first, because fuzz compilation exposes
accidental public API and decoder dependencies quickly.

Exit condition: each foundation crate passes its own tests with minimal feature
sets and has no dependency on a higher-level XPARQ crate.

### Phase 3 — Extract transaction foundations

Create `xparq-tx-base`, then extract ordinary transfer logic into
`xparq-transaction`. Keep temporary facade re-exports so node and wallet do not
need a flag-day migration.

Exit condition: transfer hashes, signatures, sizes, weights, and canonical
bytes match the Phase 0 vectors exactly.

### Phase 4 — Extract `xparq-qcash`

- Move QCash domain/file code, transaction payloads, UTXO state, proofs, and
  journals into the dedicated crate.
- Keep authenticated header-chain verification in `core` temporarily until
  `xparq-sync` exists.
- Preserve restricted visibility for raw UTXO mutation.
- Run QCash file roundtrips, proof tampering, failed-withdraw atomicity,
  redeem-delay, value-conservation, and consecutive rollback tests.

Exit condition: `xparq-qcash` can be tested without ledger, genesis, node, or
wallet dependencies, and the facade produces identical QCash bytes and roots.

### Phase 5 — Extract block and consensus

Create `xparq-block`, then `xparq-consensus`. Block types must not import
consensus policy merely to construct data. Consensus consumes immutable block
views and returns validation results.

Exit condition: proof-of-work, WBDA, block weight, reward, chain-work, and fork
choice tests pass on all network profiles.

### Phase 6 — Extract state and ledger

Create `xparq-state`, then `xparq-ledger`. Add a single integration invariant
entry point that validates account authorization, XPQ UTXOs, QCash roots,
supply accounting, journals, and state-root composition after load,
deserialization, snapshot import, transition, and rollback.

Exit condition: a ledger can be loaded, executed, saved, reopened, rolled back,
and snapshot-restored with state roots identical to the baseline.

### Phase 7 — Extract genesis and authenticated sync

Create `xparq-genesis` and `xparq-sync` only after block, consensus, state,
and ledger APIs stabilize. Revalidate every frozen artifact and trust anchor.

Exit condition: configured genesis, snapshots, checkpoints, chain-work, and
header-chain verification match the baseline.

### Phase 8 — Migrate consumers and narrow the facade

- Migrate node, wallet, examples, benchmarks, and fuzz targets to direct crate
  imports where direct ownership is useful.
- Keep common application imports available through `xparq` for one full
  compatibility cycle.
- Deprecate facade paths only after all in-repository consumers have migrated.
- Decide separately which crates are public packages and which remain internal
  workspace implementation details.

Exit condition: `core` is a thin re-export facade with no consensus execution
or canonical type definitions of its own.

## Rules for every extraction pull request

Each pull request should extract one boundary and remain reviewable. It must:

1. make no intentional wire, hash, state-root, genesis, economic, or validation
   change;
2. preserve public behavior through facade re-exports;
3. avoid simultaneous renaming and logic rewrites;
4. include old-versus-new golden-vector comparisons where canonical data moves;
5. keep package versions separate from protocol and format identifiers;
6. add no dependency from a lower layer to a higher layer;
7. document any API whose visibility becomes narrower;
8. leave vendored upstream packages under `depend/` outside workspace
   membership.

If a required extraction changes canonical bytes or persistent state, stop the
structural migration and handle it as an explicit consensus/storage upgrade.

## Validation gate

Run the following gate after every phase:

```bash
cargo fmt -p xparq -p node -p wallet -- --check
cargo test --workspace --locked
cargo check --workspace --locked --no-default-features --features testnet
cargo check --workspace --locked --no-default-features --features devnet
cargo check --manifest-path core/fuzz/Cargo.toml --locked
```

As crates are added, include every new package in formatting and ensure it can
also pass a targeted `cargo test -p <package> --locked`. Do not use
`--all-features` because the network profiles are mutually exclusive.

Before merging a phase, also verify:

- `cargo metadata --no-deps --format-version 1` shows the intended workspace
  members and only one definition of each canonical type;
- no extracted crate imports through the `xparq` facade;
- no dependency cycle is hidden behind dev-dependencies or feature flags;
- node and wallet binaries still report the expected package version;
- release packaging still includes binaries built from the same tagged commit.

## Definition of done

The decomposition is complete when:

- QCash, transaction, block, consensus, state, ledger, genesis, and sync
  have explicit crate ownership;
- the workspace dependency graph is acyclic and follows the documented layer
  direction;
- raw state mutation is not exposed across crate boundaries;
- node, wallet, tests, benchmarks, and fuzz targets no longer rely on accidental
  `core` internals;
- all baseline bytes, hashes, roots, genesis identities, and validation results
  remain unchanged;
- the `xparq` package is only a stable compatibility facade.

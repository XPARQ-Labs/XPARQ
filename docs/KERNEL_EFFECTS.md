# Kernel extension effects v2

This protocol update fixes three ledger bugs in extension effects. The code
lives under `kernel/src/ledger/`; the Cargo package and Rust library are both
named `kernel`.

## Changes

- Coin rollback journals retain only outputs that still exist at the end of a
  transition and inputs that existed before it. A change output created by one
  effect and consumed by another is cancelled in the journal. The same rule
  applies when combining fee and effect journals. Later failures and block
  disconnects therefore restore the original state.
- Asset mint and transfer IDs now include an execution origin derived from the
  genesis hash, trusted program ID, and chain-bound fee spend commitment. The
  effect index identifies an effect within that invocation. Repeated mints in
  different transactions create different shares. Existing share IDs cannot be
  overwritten by program mint/transfer operations; collision checks run before
  mutation.
- Extension coin outputs and change use distinct hash domains, separate from
  ordinary payment outputs. Effect index zero can coexist with a spendable fee
  output at index zero.

The execution origin uses `XPARQ Extension Execution v2`. Coin output and change
IDs use `XPARQ Extension Coin Output v2` and `XPARQ Extension Coin Change v2`.
These identifiers are derived by the ledger, not supplied by WASM guests.
Native coin output derivation and the parent `AssetHash` derivation are unchanged.

## Compatibility

`CHAIN_SPEC_VERSION` is now 5. Version 4 moved coin and asset-share UTXOs
into one ledger-owned map and replaces the separate transfer encodings with
the canonical `Spend::{Coin, Asset}` model. The extension protocol marker is
`xparq-extension-permissionless-wasm-effects-v2`. The genesis block and hash
remain unchanged, but the chain-spec hash changes because extension state
transitions produce different IDs.

Existing node handshake, redb metadata, and snapshot checks bind to the
chain-spec hash. An old peer, database, or snapshot is incompatible with this
version. The storage schema number is unchanged because journal encoding is
unchanged; the chain-spec check enforces the protocol boundary.

This update does not migrate or delete existing data. Deployment requires a
coordinated fresh chain/state directory or a separately implemented and validated
migration. Keep old data backed up; manually replacing its chain-spec metadata
does not perform a migration.

## Regression coverage

`kernel/src/ledger/effect_regression_tests.rs` covers chained coin transfers,
rollback after a later failing effect, consumption of a fee-created deposit,
repeated mint supply conservation, collision rejection without mutation, and
separate output domains. A signed extension transaction passes validation,
applies with a spendable fee output at index zero, and rolls back. The same
transaction is also mined into a block and disconnected through `rollback_tip`.

`kernel/tests/consolidation_compatibility.rs` retains the original genesis bytes
and native asset/share ID vectors, and freezes the new mainnet chain-spec hash.

```bash
cargo test -p kernel --locked
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

Workspace network tests require permission to open localhost sockets.

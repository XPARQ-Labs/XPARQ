# Changelog

## Unreleased migration

- Replaced nested `core/` and `node/` with focused root workspace crates and
  the `runtime` node crate.
- Removed unused duplicate `crypto/src/dependency`; vendored sources live only
  under `depend/`.
- Added atomic owner-only wallet creation and automatic transaction submission
  with explicit `--offline` output.
- Established P2P v2, redb schema v2, snapshot v2, and chain-spec v2 as one
  compatibility boundary. Old databases, snapshots, and peers require reset or
  coordinated upgrade.
- Added wallet history, paginated UTXO tracking, QCash partial redeem/change,
  and one-amount split behavior.
- Migrated release packaging to `xparq-runtime` and `wallet`.
- Retired old Docker, tutorial, roadmap, whitepaper, and legacy fuzzing files
  because they described the removed architecture. Current behavior lives in
  the root, runtime, and wallet READMEs.

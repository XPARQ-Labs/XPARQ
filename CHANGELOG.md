# Changelog

## Unreleased migration

- Replaced nested `core/` and `node/` with focused root workspace crates and
  the `runtime` node crate.
- Removed unused duplicate `crypto/src/dependency`; vendored sources live only
  under `depend/`.
- Added atomic owner-only wallet creation and automatic transaction submission
  with explicit `--offline` output.
- Established versioned P2P, redb, snapshot, and chain-spec compatibility
  boundaries. Profile-only account authorization advances them to P2P v5,
  redb schema v4, snapshot v4, and chain-spec v7. Old databases, snapshots, and peers
  require reset or a coordinated upgrade.
- Added wallet history, paginated UTXO tracking, QCash partial redeem/change,
  and one-amount split behavior.
- Added an embedded OpenAPI 3.1 specification at `/openapi.json` and an
  interactive Scalar API reference at `/docs`.
- Migrated release packaging to `xparq-runtime` and `wallet`.
- Added selectable ML-DSA-44, ML-DSA-65, ML-DSA-87, Falcon-512, and
  Falcon-1024 signature profiles. Profile-tagged account authorizations are
  active from genesis; one mnemonic derives independent, domain-separated
  addresses for each profile. Wallet creation and restoration accept `--profile`,
  default to the ML-DSA-44 profile, persist the selected profile, and automatically sign spends and withdrawals
  with it. The node account RPC reports the registered signature profile.
- Replaced scheme-specific account authorizations and key registries with the
  single profile-tagged representation on the reset chain.
- Removed the legacy fixed ML-DSA-44 `keygen` account API; all account key
  derivation, addressing, signing, and verification now use signature profiles.
- Added the height-aware textual XPQ CoinId encoding
  `xpq:<base64url-without-padding>` from height 10,000. The parser continues to
  accept legacy 64-character hexadecimal IDs and the canonical 32-byte CoinId
  and its hash derivation are unchanged.
- Retired old Docker, tutorial, roadmap, whitepaper, and legacy fuzzing files
  because they described the removed architecture. Current behavior lives in
  the root, runtime, and wallet READMEs.

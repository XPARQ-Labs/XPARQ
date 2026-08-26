# Changelog

## Unreleased migration

- Replaced nested `core/` and `node/` with focused root workspace crates and
  the `runtime` node crate.
- Removed unused duplicate `crypto/src/dependency`; vendored sources live only
  under `depend/`.
- Added atomic owner-only wallet creation and automatic transaction submission
  with explicit `--offline` output.
- Established versioned P2P, redb, snapshot, and chain-spec compatibility
  boundaries. Falcon-512 account support advances them to P2P v4, redb schema
  v3, snapshot v3, and chain-spec v4. Old databases, snapshots, and peers
  require reset or a coordinated upgrade.
- Added wallet history, paginated UTXO tracking, QCash partial redeem/change,
  and one-amount split behavior.
- Added an embedded OpenAPI 3.1 specification at `/openapi.json` and an
  interactive Scalar API reference at `/docs`.
- Migrated release packaging to `xparq-runtime` and `wallet`.
- Added selectable ML-DSA-44, ML-DSA-65, ML-DSA-87, Falcon-512, and
  Falcon-1024 signature profiles. Profile-tagged account authorizations activate
  together at height 10,000; one mnemonic derives independent, domain-separated
  addresses for each profile. Wallet creation and restoration accept `--profile`,
  persist the selected profile, and automatically sign spends and withdrawals
  with it. The node account RPC reports the registered signature profile while
  wallet files without the new field remain legacy ML-DSA-44 wallets.
- Added the height-aware textual XPQ CoinId encoding
  `xpq:<base64url-without-padding>` from height 10,000. The parser continues to
  accept legacy 64-character hexadecimal IDs and the canonical 32-byte CoinId
  and its hash derivation are unchanged.
- Retired old Docker, tutorial, roadmap, whitepaper, and legacy fuzzing files
  because they described the removed architecture. Current behavior lives in
  the root, runtime, and wallet READMEs.

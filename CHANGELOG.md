# Changelog

## Unreleased migration

- Replaced nested `core/` and `node/` with focused root workspace crates and
  the `runtime` node crate.
- Removed unused duplicate `crypto/src/dependency`; vendored sources live only
  under `depend/`.
- Added atomic owner-only wallet creation and automatic transaction submission
  with explicit `--offline` output.
- Established versioned P2P, redb, snapshot, and chain-spec compatibility
  boundaries. The current reset-chain boundary is P2P v6, redb schema v10,
  snapshot v9, and chain-spec v14. Old databases and snapshots require a reset
  or explicit migration; peers must be upgraded together.
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
- Replaced QCash ML-DSA-44 bearer authorization with fixed-size Falcon-512 keys
  and signatures (897-byte public keys and 666-byte signatures) on the reset chain.
- Replaced Bech32 addresses with canonical 50-character lowercase `0x` text:
  20 address bytes followed by a four-byte, domain-separated SHA3-256 checksum.
  Legacy Bech32 and raw 20-byte hexadecimal input are no longer accepted.
- Standardized the smallest unit name as `esca` (`1 XPQ = 1,000,000 esca`)
  and CoinId text as the case-sensitive `XPQ:` prefix followed by 64 hex digits.
- Restricted maturity metadata to block-emission UTXOs. RPC and wallet output now
  expose optional `maturity_height` and use `immature` instead of the generic
  `spendable_height`/`locked` terminology.
- Simplified QCash filenames to their canonical amount, such as `10XPQ.QCash`.
  Same-amount files receive collision-safe numbered names such as
  `10XPQ(2).QCash`; the bearer file contents, not its filename, retain identity.
- Removed the unused vendored Bech32 implementation and dependency.
- Added the selected profile's hexadecimal public key and 32-byte private
  signing seed to newly created or restored `wallet.json` files. Wallet loading
  verifies both values against the mnemonic and signature profile while
  remaining compatible with earlier profile wallet files that omit them.
- Added `xparq-asset`, `xparq-bridge`, and the `xparq-extension` facade to the
  root workspace. These crates expose optional asset/bridge primitives without
  activating bridge behavior in consensus or granting ledger mutation access.
- Added consensus-neutral core extension primitives: deterministic IDs, bounded
  canonical payloads, ordered state-root commitments, state capabilities, and
  validate/apply contracts. No asset, bridge, or DEX business primitive was
  added to core.
- Added the core extension state lifecycle with isolated namespaces, bounded
  keys/values/entry counts, staged validate/apply, host-owned root computation,
  deterministic aggregate roots, and reversible journals. Concrete runtime
  registration and extension fee policy remain explicit activation boundaries.
- Added the canonical `AuthorizedTransaction::Extension` envelope and wired it
  through structural consensus validation, staged ledger application, block
  journals, explorer decoding, snapshot/storage boundaries, and fail-closed
  production registry lookup. Miners commit the deterministic post-extension
  root in `block.header.state_root`, and block application rejects a mismatched
  root before committing either ledger or chain state. The production registry
  contains the native asset extension from genesis.
- Added signed canonical asset calls for permissionless registration, bounded
  supply, authority-only minting, owner burn/transfer, balances, and replay-safe
  account nonces. Each asset call carries an authorized XPQ fee spend; fee and
  asset transitions apply and roll back atomically. Added asset query RPCs and
  wallet commands for register, mint, burn, transfer, metadata, and balances.
  The interactive wallet exposes the same operations through an Assets submenu.
  Asset registration stores a bounded human-readable token name separately from
  its normalized uppercase symbol.
  Asset supply, limits, balances, and operation amounts use canonical `u128`;
  RPC responses encode these values as decimal strings without precision loss.
  Explorer transaction projections now decode asset calls and expose the asset
  ID and action. Account balance responses and the wallet balance screen list
  held assets plus zero-balance assets controlled by the mint authority.
- Retired old Docker, tutorial, roadmap, whitepaper, and legacy fuzzing files
  because they described the removed architecture. Current behavior lives in
  the root, runtime, and wallet READMEs.

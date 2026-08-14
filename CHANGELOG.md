# Changelog

All notable changes to XPARQ are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning for software releases. Consensus,
storage, wallet, and peer compatibility boundaries are called out explicitly;
the version number alone must not be treated as a database migration mechanism.

## [Unreleased]

No unreleased changes yet.

## [0.2.13] - 2026-08-13

### Fixed

- Fixed peer common-ancestor discovery accepting a known side-branch hash and
  then serving canonical headers from the same height. Diverged nodes now anchor
  historical synchronization only to a hash on the responding peer's canonical
  chain instead of repeatedly rejecting valid headers and eventually banning a
  compatible higher-work peer.
- Renamed the user-facing `Wallet passphrase` prompt and documentation to
  `Wallet password` and clarified that it is free-form key-derivation input,
  not a mnemonic word-count selection or encryption of the stored mnemonic.
- Bounded temporary LMDB maps during Windows release tests so the full node and
  wallet test suite fits on the hosted runner without changing runtime defaults.

## [0.2.12] - 2026-08-13

### Added

#### Core and consensus

- Added network-bound Argon2id proof of work using the chain ID and a
  parent-derived salt.
- Added chain-spec commitment and peer compatibility checks for consensus
  policy that is intentionally separate from the frozen empty genesis header.
- Added cumulative-work fork choice with the lower numerical tip hash as the
  deterministic tie-breaker.
- Added explicit trusted-checkpoint support, authenticated header-chain
  verification, and checkpoint-aware incremental reorganization.
- Committed the owned-XPQ UTXO root into the protocol state root and extended
  ledger invariants across account, XPQ UTXO, and QCash UTXO state.

#### QCash

- Added exact flexible-value QCash outputs down to one paq (`0.000001 XPQ`).
- Added multi-output withdrawal in one transaction. The wallet accepts
  `cash withdraw TOTAL --amounts AMOUNT,AMOUNT,...`; the selected positive
  amounts must sum exactly to `TOTAL`, are canonically ordered from largest to
  smallest, and create independently redeemable bearer files.
- Limited a QCash withdrawal to 256 outputs and assigned every output its own
  index, redeem-key commitment, coin ID, opening secret, and `.QCash` file.
- Added partial redeem with QCash change and pure split into multiple QCash
  outputs, with value conservation across the recipient, QCash change, and an
  optional miner output.
- Added canonical rollback behavior for withdrawals, redeems, and splits,
  including restoration of consumed QCash UTXOs when their block is
  disconnected.

#### Node and networking

- Added bounded cryptographic and state-work queues, parallel synchronization
  stages, bounded orphan handling, and recent-block caching.
- Added peer handshake checks for chain identity and consensus compatibility.
- Added persisted per-block reorganization journals and atomic persistence of
  accepted blocks with dirty account, XPQ, and QCash state.
- Added RPC, explorer, lifecycle-event, and mempool handling for the revised
  transfer and QCash transaction structures.
- Added Prometheus measurements for RPC, queue, synchronization, verification,
  application, and cache behavior.

#### Wallet

- Added multi-output QCash withdrawal through CLI and interactive-menu
  `--amounts` input.
- Added flexible-value QCash bearer filenames containing the complete 32-byte
  coin ID, plus inspect, track, backup, and recovery workflows.
- Added full and partial redeem and split workflows with automatic or explicit
  miner fees and safe cleanup of newly generated files when node submission is
  rejected.
- Added authenticated proof-checkpoint persistence beside wallet files.

#### Operations and documentation

- Added a multi-stage Docker build, Compose configuration, and an example
  mainnet node configuration.
- Updated the README, tutorial, whitepaper, crate documentation, fuzzing guide,
  and roadmap to describe the active L1 protocol and operator workflow.
- Updated release automation to validate and publish the active `node` and
  `wallet` packages and binaries.

### Changed

#### Consensus and monetary policy

- Changed account addresses to 20 bytes and bound each address to its active
  authorization public key.
- Set the base block subsidy to 5 XPQ. WBDA evaluates each completed
  4,100-block epoch against a 5 MiB target, adjusts difficulty and subsidy at
  the next epoch boundary, and clamps subsidy to `0.5..=10 XPQ`.
- Separated the stable frozen genesis identity from tunable consensus policy;
  network IDs are `707` for devnet, `717` for testnet, and `747` for mainnet.
- Unified consensus encoding and hashing behind canonical, domain-separated
  serialization paths.

#### Transactions and QCash

- Changed XPQ accounting to deterministic transaction-hash/output-index UTXOs
  with explicit change outputs.
- Changed QCash from fixed denominations to exact amounts in paqs.
- Changed withdrawal fees to be paid from selected on-chain XPQ inputs; the
  requested QCash output total is not reduced by the fee.
- Changed redeem and split fees to use at most one ordinary `BlockMiner`
  output and apply the same virtual-byte fee policy as transfers and
  withdrawals.
- Changed QCash files and coin identifiers to bind each bearer coin to its
  withdrawal transaction and output metadata.

#### Chain and node behavior

- Changed synchronization and reorganization to select valid branches by
  cumulative proof of work rather than height alone.
- Changed transaction lifecycle finality at depth five to an API and wallet
  confidence status only; it does not prevent a greater-work reorganization.
- Changed hard checkpoints to require an explicitly authenticated snapshot or
  checkpoint trust anchor. Locally observed WBDA boundaries are not automatic
  checkpoints.
- Changed release and operator naming to the active `node` and `wallet`
  packages and binaries.

### Removed

- Removed the sidechain workspace, bridge-oriented scaffold, wrapped-token and
  native-token programs, sidechain primitives, and their active documentation.
  Version 0.2.12 is intentionally scoped to the L1 `core`, `node`, and `wallet`.
- Removed automatic buried-WBDA checkpoint creation.
- Removed manual on-chain QCash recovery and the legacy recovery event.
- Removed obsolete verification-cache, recovery, and duplicated internal test
  modules superseded by the current core and node architecture.

### Security

- Bound PoW work to its network and parent context to prevent reuse across
  incompatible chains or parent histories.
- Enforced authorization-to-address binding and strengthened transaction,
  UTXO, state-root, snapshot, proof, and rollback invariants.
- Kept QCash opening secrets out of ledger state and used a distinct secret for
  every withdrawal output. A `.QCash` file remains bearer value and must be
  protected against copying, theft, and premature disclosure.
- Added bounded queues and buffers to reduce resource-exhaustion exposure in
  cryptographic verification, state work, synchronization, and orphan storage.

### Compatibility and migration

- **Breaking:** databases, blocks, snapshots, checkpoints, wallets, and
  addresses from version 0.2.11 or earlier, 32-byte-address builds, the former
  PoW construction, or builds that generated automatic buried-WBDA
  checkpoints are incompatible with 0.2.12.
- Operators must stop the old node, preserve any backups needed for audit,
  initialize a fresh database for the selected network, and regenerate or
  restore wallets from their mnemonic under the 0.2.12 format.
- Old `.QCash` files and incompatible proof/checkpoint artifacts must not be
  assumed valid under the new format. There is no implicit database or bearer
  file migration.
- Mixed-version peers are intentionally rejected when their chain identity or
  committed consensus policy differs.

[Unreleased]: https://github.com/XPARQ-Labs/XPARQ/compare/v0.2.13...HEAD
[0.2.13]: https://github.com/XPARQ-Labs/XPARQ/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/XPARQ-Labs/XPARQ/releases/tag/v0.2.12

# Changelog

All notable changes to Paqus Sharksphere are documented in this file.

The comparison baseline for this changelog is Paqus 0.2.17, commit
`18aac16` (`Release paqus 0.2.17`). The repository does not contain a
`v0.2.17` tag.

## [0.2.18] - 2026-07-30

Paqus 0.2.18 is a consensus-breaking development release. Existing chains,
databases, serialized transactions, blocks, addresses, and QCash files from
0.2.17 must not be reused without an explicit migration. Development networks
are expected to reset or resynchronize their chain state.

Protocol, block, transaction, QCash transaction, artifact, and file-format
version constants remain `1`. Equality of those numeric fields does not imply
binary or consensus compatibility with 0.2.17.

### Added

- Added default dual authorization for Transfer, QCash, and Governance. Every
  outgoing transaction requires an owner ML-DSA-44 signature and an
  authorization ML-DSA-44 signature over the same chain-bound payload.
- Added dual-authorization addresses derived from the ordered owner and
  authorization public-key pair using the
  `PAQUS_DUAL_AUTHORIZATION_V1` domain and chain ID.
- Added account-state authorization registration. A recipient can receive XPQ
  before registration; the first outgoing transaction registers both public
  keys in authenticated account state.
- Added signature-only stored-key witnesses. After registration, transactions
  omit both 1,312-byte public keys and retain only the two 2,420-byte
  signatures.
- Added parallel verification of the two ML-DSA-44 transaction signatures.
- Added unified multi-output Transfer transactions with 1–64 outputs. A
  one-output Transfer replaces the former separate single-transfer form.
- Added a unified signed protocol envelope and one ordered execution lane for
  Transfer, QCash, and Governance transactions.
- Added Argon2id proof of work with 64 MiB memory, one iteration, one lane, and
  per-block ASERT difficulty adjustment.
- Added cumulative-chainwork fork choice with deterministic tie handling.
- Added frozen-genesis header-chain verification, trusted header checkpoints,
  and checkpoint-extension verification.
- Added authenticated account membership/non-membership and QCash state-proof
  bundles with checkpoint-based compact verification.
- Added authenticated genesis, checkpoint, and snapshot artifacts with
  chain-spec, checkpoint, state-root, and payload-integrity commitments.
- Added authenticated snapshot ledger restoration and a pinned checkpoint
  boundary for pruned pre-snapshot history.
- Added typed protocol state commitments combining account, QCash, credential,
  and governance roots.
- Added governance issuers, credentials, credential binding/revocation,
  proposals, voting, finalization, execution, balance locks, and rollback.
- Added canonical protocol events for transfers, QCash, governance, genesis
  allocations, coinbase payments, and miner fee revenue.
- Added QCash membership and non-membership proofs and canonical-chain spend
  tracing by opaque `coin_id`.
- Added expanded standardized QCash denominations through 1,000,000 XPQ.
- Added block witness-key dictionaries and separate transaction (`txid`) and
  complete-witness (`wtxid`) commitments.
- Added `CHAINSPEC.md` containing the implemented chain identity, consensus
  parameters, lifecycle, QCash rules, and consensus/policy boundary.
- Added password-protected `PGD1` governance credential files using an
  Argon2id-derived key and XChaCha20-Poly1305, authenticated against the chain
  ID and frozen genesis.

### Changed

- Changed Transfer encoding to one canonical `Vec<TransferOutput>` with a
  minimum of one and maximum of 64 unique non-zero recipients.
- Changed registered-account witnesses to resolve both authorization public
  keys from account state instead of repeating them in every transaction.
- Changed transaction signing contexts to bind the family domain, chain ID,
  protocol version, frozen genesis hash, and complete canonical payload.
- Changed confirmation depth to 2 blocks and the local finality/reorganization
  boundary to 5 blocks.
- Changed QCash withdrawals so bearer coins are active in their inclusion
  block and become eligible for deposit one block later.
- Changed credits produced by a QCash deposit to follow the normal two-block
  account-credit maturity.
- Changed block reward maturity to 50 blocks.
- Changed witness weight accounting to use the complete serialized size.
  `WITNESS_SCALE_FACTOR` is 1, so witness bytes receive no consensus discount.
- Changed maximum block weight to equal the 5 MiB maximum serialized block
  size.
- Changed QCash denomination consensus encoding from `u16` to `u32`.
- Strengthened atomic execution, account/QCash rollback journals, state-root
  validation, transaction duplication checks, hostile decode bounds, and
  economic-supply invariants.
- Documented node relay, market, and miner fee rates as policy measured in
  integer `paqus/vByte`; fee amounts included in blocks remain consensus data.
- Declared Rust 1.90 as the minimum supported Rust version tested for this
  release.
- Completed wallet commands and interactive-menu routes for all nine
  Governance actions plus encrypted bearer-credential creation.

### Removed

- Removed the separate single-recipient Transfer representation.
- Removed repeated public keys from normal transactions after account
  authorization registration.
- Removed support for spending a dual-authorization account with only one
  signature.
- Removed the previous ten-block QCash withdrawal/deposit maturity behavior.
- Removed the witness size discount from fee and block-weight calculations.
- Removed acceptance of plaintext governance credential files.

### Security

- A leaked owner secret key is insufficient to spend without the independent
  authorization secret key, and the reverse is also true.
- Both public keys are cryptographically bound to the account address and both
  signatures authorize identical chain-bound bytes.
- Public keys stored in account state are public verification material; secret
  keys and QCash opening secrets never enter consensus state.
- Snapshot artifacts are accepted only against a checkpoint established by a
  locally verified proof-of-work header chain rooted at frozen genesis.
- Fork choice uses locally calculated cumulative work rather than advertised
  height or peer-supplied work claims.
- QCash rollback removes outputs created on disconnected branches and restores
  UTXOs consumed by disconnected deposits.
- Governance credential containers enforce file magic/version, a 16 KiB input
  bound, authenticated encryption, and secret/public-key matching. Secret
  keys are redacted from `Debug`.
- Credential-use signatures now bind the authorized signer address in addition
  to context and nullifier, preventing mempool copy-and-race reassignment.

### Compatibility and migration

- Reset or resynchronize blockchain databases created by 0.2.17.
- Clear persisted mempool entries and serialized transaction caches.
- Recreate addresses whose derivation predates dual authorization.
- Recreate incompatible QCash files and transactions from earlier development
  formats.
- Upgrade core, node, and wallet together. Mixed 0.2.17/0.2.18 deployments are
  unsupported.
- Do not regenerate frozen consensus vectors silently. Any intentional vector
  change requires an explicit consensus decision.

### Validation

- Mainnet core suite: 94 passed, 0 failed.
- Testnet core suite: 97 passed, 0 failed; one explicitly expensive SQIsign
  Level 5 end-to-end test remained ignored.
- Devnet chain identity/genesis, coinbase supply transition, and WitnessV2
  network-signature checks: passed.
- Core documentation tests: passed.
- Packaged-crate verification against crates.io dependencies: passed.
- `cargo publish --dry-run`: passed.

## [0.2.17]

Baseline release represented by commit `18aac16`.

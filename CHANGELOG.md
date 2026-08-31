# Changelog

## Unreleased migration

- Replaced nested `core/` and `node/` with focused root workspace crates and
  the `runtime` node crate.
- Removed unused duplicate `crypto/src/dependency`; vendored sources live only
  under `depend/`.
- Added atomic owner-only wallet creation and automatic transaction submission
  with explicit `--offline` output.
- Established versioned P2P, redb, snapshot, and chain-spec compatibility
  boundaries. The reset chain starts at P2P v1, redb schema v1, snapshot v1,
  and chain-spec v1. Old databases and snapshots require a reset
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
- Standardized the smallest unit name as `zeno` (`1 XPQ = 100,000 zeno`)
  and CoinId text as the case-sensitive `XPQ:` prefix followed by 64 hex digits.
- Added consensus state-growth charging through `OutputTarget::Burn` at
  `STATE_BURN_RATE_ZENO_PER_WEIGHT`. Every newly created state entry is charged
  without credit for consumed inputs. Burn outputs conserve transaction value
  but never enter the UTXO set; wallet builders calculate them automatically.
  Native asset calls count every newly persisted metadata, supply, balance, and
  nonce key plus its canonical value, rather than charging metadata alone.
  Every non-genesis emission pays the same Coin UTXO creation burn before
  distribution: WBDA determines gross subsidy, the miner receives the net
  reward, and the deducted amount participates in checked burn rollback.
  Ledger state tracks checked `total_burned`, including rollback/reorg, and the
  node exposes it through `GET /status`.
- Native asset supply and balances use `u128`. Native XPQ `Amount` remains a
  canonical eight-byte `u64`; migrating it to `u128` is a separate breaking
  consensus change and is not claimed by this reset-chain build.
- Removed coin maturity from consensus and storage. Block-emission outputs are
  immediately transferable by height rules, and RPC/wallet UTXOs expose only
  local mempool reservation status without a second available-balance field.
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
  its normalized uppercase symbol. Registration atomically mints the requested
  initial supply to the creator address in the same transaction; distribution
  to other addresses is an explicit transfer by the creator.
  Asset supply, limits, balances, and operation amounts use canonical `u128`;
  RPC responses encode these values as decimal strings without precision loss.
  Explorer transaction projections now decode asset calls and expose the asset
  ID and action. Account balance responses and the wallet balance screen list
  held assets plus assets controlled by the mint authority.
- Added deterministic WASM extension ABI v1 using an interpreter with fuel,
  fixed memory, bounded state snapshots, canonical Borsh packages, code-hash
  identities, and read-only validation. Nodes can load reviewed `.xpqext`
  packages with `--extension-package` without rebuilding; the ordered manifest
  allowlist is committed into the effective chain-spec hash so peers and stored
  databases fail closed when their WASM packages differ. Native-only nodes keep
  the existing chain-spec identity.
- Added immutable permissionless WASM deployment as an atomic signed extension
  transaction. The node validates and stores bytecode in consensus state,
  derives its ID from name and code hash, and activates it automatically 100
  blocks after inclusion. Dynamic execution resolves code from ledger state, so
  replay, snapshots, state roots, and reorg rollback do not depend on process
  memory. Wallet deploy/info commands and WASM nonce/status RPCs are included.
- Activated generic signed WASM application calls from genesis on the reset
  chain. Calls bind the chain ID,
  extension ID, payload, signer, and per-extension nonce. The wallet provides
  `wasm-call`; node RPC exposes nonce and exact extension-state preview routes.
  Starting at activation, deployment and application state burn covers every
  newly persisted extension key and value, not only metadata.
- Retired old Docker, tutorial, roadmap, whitepaper, and legacy fuzzing files
  because they described the removed architecture. Current behavior lives in
  the root, runtime, and wallet READMEs.

# ProgramCall integration

See [architecture](ARCHITECTURE.md), [XPVM](XPVM.md), and
[wallet commands](../wallet/README.md#extension-asset-program).

## Canonical operations and identities

Blocks contain `BlockOperation::ProgramCall` or `BlockOperation::DeployProgram`.
`AuthorizedProgramInvocation` signs a call and its `CoinTransition` together;
`AuthorizedProgramEnvelope` is the canonical transaction envelope used by RPC.
Deploy uses `AuthorizedDeployProgram` and its separate authorization path.
The unused standalone AuthorizedProgramCall API and legacy.rs were removed.
Active preparation helpers live in `kernel::program::preparation`.

| Identity | Meaning |
| --- | --- |
| SystemProgramId(u32) | Dispatcher route: MONETARY=0, VM=2; route 1 is a legacy asset decoder alias |
| ProgramId (32 bytes) | Owner instance: implicit signature policy or deployed bytecode |
| Asset contract ID | Canonical asset identity, separate from the owning program |

One monetary system program handles all monetary methods:

| Opcode | Operation | Payload |
| --- | --- | --- |
| 1 | Transfer | Currency byte: 0 coin, 1 asset; then currency-specific data |
| 2 | Create asset | Canonical Register payload |
| 3 | Mint asset | Canonical Mint payload including asset contract |
| 4 | Burn | Currency byte: 0 coin, 1 asset; then currency-specific data |

Coin transfer uses currency byte 0 with no additional data: its inputs, outputs
and miner fee come exclusively from the signed payment. The historical empty
coin-transfer payload remains accepted. Asset transfer/burn append their bounded
canonical payload after currency byte 1. Unknown currencies, malformed data and
voluntary coin burn are rejected. Create and mint retain their asset-specific
rules. Route 1 only decodes historical asset opcodes into the same implementation;
it is not another installed application. Wallets emit route 0.

VM route 2, opcode 0 receives a deployed instance hash as payload; opcode 1 appends
bounded application calldata. Monetary application execution lives in
`extension::monetary`; VM execution and checked monetary hosts remain in kernel.

## State ownership and authorization

Kernel owns coin UTXOs and counters, `LedgerState.extensions.assets`, and
`LedgerState.programs`. Asset shares are not coin UTXOs. Extension receives
restricted hosts rather than mutable LedgerState. Runtime installs
`extension::SystemApplications` for preview, commit, replay, mempool and quotes,
and reinstalls it on snapshot load. Executor capabilities are not serialized.

The coin host binds consumption, program-owned outputs, miner fee and burn to the signed
payment. AssetHost binds its one operation to the signed asset instruction.
Kernel checks ownership, mint nonce, conservation and supply. Coin supply obeys
`total_mined - total_burned = sum(live coin UTXOs)`; asset supply is reconciled
against live asset shares independently.

`validate_program_call_with_applications` authenticates the call and payment
against chain and height. Call and payment signer must agree. Protocol burn covers
canonical transaction archival weight and positive state growth; miner fee is
separate. Asset growth is the positive difference in canonical extension-state
bytes. Net created coin UTXOs include an optional miner-fee output. State shrinkage
provides no refund.

## Atomic execution and rollback

`LedgerState::apply_program_call_with_applications` and
`apply_deploy_with_applications` validate and apply on staged state. Payment,
application effects and supply checks must succeed before commit. Coin, asset
and program journals preserve prior values for rollback. Block rollback checks
the expected tip and parent state roots before committing the restored state.
Snapshots contain canonical state and rollback journals, not application executors.

## RPC and wallet

| Endpoint | Canonical request / purpose |
| --- | --- |
| POST /transaction | Signed Borsh AuthorizedProgramEnvelope; submits a ProgramCall |
| POST /program/quote | Signed Borsh AuthorizedProgramEnvelope; quotes asset state growth without admission |
| POST /program/deploy | Signed Borsh AuthorizedDeployProgram, without BlockOperation wrapper |
| POST /program/deploy/quote | Draft Borsh AuthorizedDeployProgram before signing; validates deploy structure and returns commitment/burn |
| GET /program/asset/{asset} | Metadata, supply and mint nonce |
| GET /program/asset/{asset}/balance/{program_id} | Balance and owned shares |

Program quote verifies authorization but does not validate exact payment burn.
VM quotes also check payment input ownership/conservation and program balances. It returns `created_state_weight`, `vm_fuel` (zero for non-VM calls), and
canonical `tip_hash`, plus `vm_return_value` as a decimal string for VM calls.
VM quotes preview the current registry, storage, and monetary state;
they reject missing programs, invalid code, overflow, and exhausted fuel. VM
payments must include one zeno of burn per fuel unit in addition to existing
state and archival burn.
Deployment quote returns `program_id`, `required_protocol_burn`,
`authorization_commitment`, next-block `height` and `tip_hash`. Quotes can become
stale; submission revalidates against current mempool state. A state-growth quote
is not a VM fuel quote. RPC monetary values use raw units; wallet amount inputs
use 8 decimals.

Asset CLI commands cover register/mint/transfer/burn/consolidate/info/balance.
`program-register` creates an asset; `program-deploy` deploys bytecode. Account
and balance responses expose `program_assets`. Explorer indexes include asset
recipients even when they receive no XPQ. See [OpenAPI](openapi.json) for routes.

## Storage and compatibility

Current chain spec version is **1**, storage schema **1**, and newly written
snapshot version **3**. The snapshot loader supports the legacy v1 representation
only when its decoder and chain/schema checks accept it; v2 is not accepted by
this loader. Snapshots must match chain identity, checksum, canonical log and
state invariants. If no snapshot qualifies, startup replays from genesis.

The reset baseline requires fresh compatible chain storage. Schema-mismatched
databases are rejected, not automatically migrated; legacy asset balances are
not imported. The chain-spec hash commits to the actual rules and formats; a
version number alone cannot make incompatible state readable.

## Verification status and remaining gates

On 8 October 2026, after the salted-account and 32-byte share changes, the full
workspace test suite passed. Coverage includes authorization, monetary effects,
VM, supply and state roots, snapshot/restart, mempool persistence, and network
sync/reorg. The three-node program lifecycle passed as part of the network suite
(8 tests, 121.53 s). The `litep2p-devnet` all-target build check also passed.
Rust formatting, Markdown local links and OpenAPI JSON are checked separately.
Existing vendor warnings remain; these checks do not replace a security audit.

The chain-spec identity fixtures and Phase 4 vectors are reconciled for version 1:
`bounded_work_rules_have_frozen_mainnet_chain_spec_identity`,
`frozen_phase4_vectors_match_execution`, and
`mainnet_genesis_and_chain_spec_match_the_current_structure` pass.
The explicitly enabled wallet CLI lifecycle tests last passed on 3 October 2026;
they were not rerun as part of the default workspace suite on 8 October.
See [roadmap](../ROADMAP.md) and [security gates](SECURITY_ROADMAP.md).

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline
cargo check --workspace --all-targets --offline
cargo test --workspace --offline
cargo build -p node -p wallet --bins --offline
cargo test -p wallet --test program_e2e --offline -- --ignored --test-threads=1
cargo test -p node --test network_e2e --offline program_lifecycle_gossips_across_three_nodes_and_rolls_back_on_reorg -- --nocapture
```

Node integration checks bind local RPC/P2P sockets. GUI work remains deferred.

## Universal ownership

See [ownership design](OWNERSHIP.md). Coin-share owners, asset-share owners,
creators, mint authorities, signer, payment principal and deployer all use
ProgramId. Public keys and signatures appear in authorization proofs. Program IDs
have one display/CLI/RPC format: exactly 64 hexadecimal characters. Public RPC
owner objects have type `program` and a hex value. Legacy wallet-identity endpoints
are removed; balance/history queries operate on ProgramId.

Chain-spec version 1 and database schema 1 require an updated node and a new
compatible database. No existing-chain migration is provided.


## Salted signature accounts (chain-spec 7)

Every `AccountAuthorization` encodes `salt: [u8;32]`, then the existing public-key
and signature fields. This is a fixed 32-byte array, not a length-prefixed Vec.
The signature-policy v2 derives the signer from scheme, key and salt. The call,
signer, payment and chain are already bound by the signed commitment, so changing
salt or relabeling a signer cannot replay an authorization across accounts. The
same proof layout applies to deploy authorization. Quote/submission APIs consume
this updated canonical binary format. Salted authorization preserves the Owner
layout; the subsequent chain-spec 8 change expands share IDs to 32 bytes. Node quoting and wallet sizing include the additional 32 proof bytes.

## Full-width share identifiers (chain-spec 8)

CoinShare and asset Share use full domain-separated SHA3-256 outputs: 32 bytes
in canonical encoding and 64 hexadecimal characters in CLI/RPC/explorer output.
The old 16-byte ID encoding is rejected. Canonical coin UTXO state weight is
73 bytes (32-byte ID, 8-byte amount, 1-byte Owner tag and 32-byte ProgramId).
State-growth burn automatically uses this weight; archival burn measures the
updated transaction bytes. Database schema 1 rejects incompatible old storage.

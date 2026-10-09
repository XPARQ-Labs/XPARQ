# Kernel visibility and cross-module dependency audit

Scope: first-party kernel modules and their callers in runtime, extension,
wallet, devkit, integration tests and examples. This is a source/API audit,
not an independent security review. Public visibility was checked against
workspace usage and types exposed in public signatures; absence of a caller
alone was not treated as a reason to remove a useful API.

## Changes

| Item | Result |
| --- | --- |
| `AssetState.records` | Private to asset state; ledger accounting and fixtures use the immutable `records()` accessor |
| `Applications` executor field | Private; callers use `executor()` |
| `vm_app::valid_storage` | Restricted to `program`; registry validation and VM execution still share one check |
| `ledger::applied` | Private implementation module; public inherent ledger/state methods remain accessible |
| Application host `StateError` imports | Import the defining `error` module directly instead of the ledger re-export |

None of these changes changes hash framing, canonical fields, serialization,
validation order or execution behavior. External Rust callers that used the
removed module/helper paths must update their imports. No new errors or hash
domains were introduced.

## Visibility boundaries retained

Coin insertion/consumption, asset application/rollback, registry mutation, VM
commit and settlement are crate-private. Asset inspection returns immutable
references; the private execution context cannot be supplied by external
applications. `ApplicationExecutor`, `AssetHost` and `CoinHost` remain public
because extension installs the implementation through those contracts.

VM preview, call decoding, bytecode validation, quote types and consensus quote
validation remain public: RPC, wallet and devkit use these paths. `StateMap`
remains publicly nameable because public read accessors return that type;
its mutation methods do not grant mutation through an immutable reference.

`Ledger.state` and every `LedgerState` component are now crate-private.
External callers use `state()`, `utxos()`, `coin()`, `programs()` and
`extensions()` to inspect immutable data. `StateRootCache` is crate-private.
The detached state's `state_root()` is read-only and does not establish valid
execution. Coin/asset records and detached serialization DTOs remain data;
they cannot be directly installed through a public state setter.

`Ledger` retains its canonical Borsh serialization but no longer implements
`BorshDeserialize`. Snapshot data is decoded separately and restored through
the snapshot APIs. Legacy snapshot test/loading fixtures decode a private
untrusted DTO, then pass state/journals through restoration. Public mutation
methods on detached `LedgerState` still validate signed operations.

Residual boundary: `Ledger.chain` remains public and mutable. This change closes
direct monetary state replacement; it does not seal every part of `Ledger`.
Separately narrowing chain access requires migration of header/sync fixtures
that deliberately build synthetic chains. `from_snapshot` trusts previously
validated local history and checks state consistency; it is not a transaction
replay or PoW admission endpoint. The default body-cache restoration path verifies
PoW. The explicit trusted measured path skips historical PoW and requires a
checkpoint bound to previously validated local history; runtime enforces this
binding. See [restart validation](../RESTART_VALIDATION.md) for fallback and full
replay behavior.

Prepared calls expose mutable payload/burn fields even though their private
height prevents external construction. This is not a sealed authorization
token. Turning prepared values into immutable capabilities would require a
separate API change and review of every application entry point.

## Cross-module dependencies

| Relationship | Assessment |
| --- | --- |
| Monetary types to ledger | No production ledger ownership dependency found in monetary types; asset state is ledger-owned |
| Blockchain to program | Operation encoding includes program envelopes; this is a wire-format dependency |
| Ledger to consensus | Block admission, program-call validation, supply/burn checks and fork types are required by commit/replay |
| Consensus to program | Authorization, code execution previews and protocol application contracts are needed for validation |
| Consensus to ledger | `ProgramStateView` optionally exposes concrete ledger state for VM preview; this is an existing coupling |
| Program to ledger | VM execution/settlement and bound asset hosts use ledger state and journals; this is an existing coupling |
| Program preparation to consensus | State-growth quotes return `ProgramConsensusError` and burn errors; policy and execution errors are coupled |
| Asset supply to ledger error | Incremental supply auditing returns `LedgerError`, consistent with full ledger accounting |

The internal module graph has cycles. Splitting files has not made it a strict
layered graph. The workspace crate boundary remains `runtime -> extension ->
kernel -> crypto`, with runtime also using kernel directly; kernel does not
depend on extension or runtime.

Potential future work, only when independently motivated: introduce a narrower
VM preview state interface, or move preparation quote orchestration into
consensus. Both require behavior/API review; replacing the concrete ledger
with a trait without changing responsibilities would merely hide the coupling.
The audit does not recommend another mechanical file split.

## Verification

Passed: 44 ledger tests (including frozen canonical vectors), 23 VM/settlement
tests, one bound asset-host test, five extension capability tests, and four
kernel compile-fail documentation tests. Eight existing manual ledger tests
remain ignored.

Workspace checks passed with all targets. Kernel all-target checks also passed
separately with devnet and testnet selected and default features disabled.
Kernel Clippy passed with warnings denied; formatting and diff whitespace checks
passed. The devnet dependency build reports existing vendored SQIsign dependency
warnings. The entire workspace test suite was not run for this scoped audit.

The subsequent monetary-state encapsulation change adds four compile-fail
documentation checks for direct state replacement, counter mutation, mutable
access through a read accessor, and raw live-ledger deserialization. Snapshot
tests corrupt serialized detached data instead of live state; RPC deployment
fixtures now execute signed deployment through block admission. Broader strict
Clippy was attempted and encountered pre-existing empty lines after outer
attributes in `wallet/src/lib.rs`; strict kernel Clippy remains clean.

Encapsulation validation passed: 44 ledger tests, five supply-invariant tests,
eight kernel documentation tests, five extension boundary tests, eleven runtime
snapshot/storage tests, and one test each for deployment RPC, failed reorg,
mempool prefix invalidation and wallet authorization (77 passed; eight existing
manual ledger tests ignored). Workspace all-target checks and separate kernel
testnet/devnet all-target checks passed. Changed runtime files passed targeted
format checks. Full workspace tests were not rerun.

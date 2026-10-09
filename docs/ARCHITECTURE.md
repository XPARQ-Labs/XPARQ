# Architecture and source ownership

The [hash/error audit](audit/hash-error-audit.md) records unused-domain/error
cleanup. The [single-prefix hash v2 proposal](HASH_PROTOCOL_V2.md) specifies a
future protocol change; active hash framing is unchanged.

Dependencies flow from `runtime -> extension -> kernel -> crypto`; runtime also
uses kernel directly. Kernel has no dependency on extension.

The [kernel API and dependency audit](audit/kernel-api-dependencies.md) records
visibility boundaries and the remaining internal program/consensus/ledger
couplings. Internal modules do not form a strictly acyclic layered graph.

| Source | Responsibility |
| --- | --- |
| [kernel monetary](../kernel/src/monetary/mod.rs) | Coin/asset types and checked monetary primitives |
| [kernel program](../kernel/src/program/mod.rs) | Authorization, preparation, system-call contracts, restricted hosts, deployed registry and VM |
| [kernel ledger](../kernel/src/ledger/mod.rs) | Coin UTXOs, asset shares/accounting state, atomic application, state roots and rollback |
| [extension applications](../extension/src/applications.rs) | Installs the unified monetary application implementation |
| [monetary application](../extension/src/monetary/mod.rs) | Shared monetary program: coin transfer and asset create/mint/transfer/burn through checked hosts |
| [runtime](../runtime/src/main.rs) | Persistence, network, mempool, mining, RPC and application installation |
| [wallet](../wallet/README.md) | Signing, payment selection and user workflows over RPC |
| [devkit](../devkit/README.md) | XPVM assembler, kernel bytecode validation and isolated devnet workflows |

## Consensus validation and fork choice

`kernel/src/consensus/program_call.rs` exposes the existing validation API.
Its private modules separate the read-only state contract (`state_view.rs`),
authorization, VM preview and burn validation (`validation.rs`), input ownership
and value conservation (`payment.rs`), errors and regression tests.

`kernel/src/consensus/fork.rs` exposes the existing fork API. Private modules
separate chainwork arithmetic (`work.rs`), block admission and ancestry
(`graph.rs`), deterministic tip ordering (`ordering.rs`), validated reorganization
plans (`reorg.rs`), errors and chainwork tests. Public types, serialized fields,
validation order and fork ordering remain unchanged.

`kernel/src/consensus/policy.rs` groups three private policy modules:
`difficulty.rs` owns WBDA utilization, epoch windows and target adjustment;
`emission.rs` owns the subsidy schedule, emission authorization and origin hash;
`burn.rs` owns canonical wire weights and checked archival/state-growth charges.
Each module keeps its policy constants beside its calculations. Existing exports
through `kernel::consensus` remain available. Tests cover utilization thresholds,
epoch history access, subsidy boundaries, exact encoding sizes and overflow.

## Canonical ledger modules

`kernel/src/ledger/canonical.rs` defines `Ledger`, its common accessors and historical
burn receipts. Private modules under `kernel/src/ledger/canonical/` separate the
remaining responsibilities:

| Module | Responsibility |
| --- | --- |
| `execution.rs` | Staged block execution, commitment previews and canonical commit |
| `snapshot.rs` | Snapshot data and restoration from block history |
| `rollback.rs` | Rollback journal retention and atomic tip rollback |
| `accounting.rs` | Coin/asset supply audits and block burn accounting |
| `state_root.rs` | Canonical state encoding and cached state roots |
| `state_view.rs` | Read-only program consensus view |
| `error.rs` | Ledger errors and conversions |
| `tests.rs` | Atomicity, snapshot, replay and rollback regression tests |

These modules implement the existing `Ledger` and `LedgerState` APIs. Public
paths through `kernel::ledger` and `kernel::ledger::canonical` remain available.
Execution and rollback stage
changes before committing; canonical field order and encoding are unchanged.

External callers inspect monetary state through immutable accessors:
`Ledger::state()` and `LedgerState::{utxos, coin, programs, extensions}`.
Their backing fields and root cache are crate-private. `Ledger` supports
canonical serialization; raw Borsh deserialization into a live ledger has been
removed. Decode detached snapshot data and restore it against trusted local
history. `Ledger.chain` remains an existing mutable API, as recorded in the
visibility audit.

`kernel/src/ledger/applied.rs` groups the private operation application modules
under `kernel/src/ledger/applied/`:

| Module | Responsibility |
| --- | --- |
| `coin.rs` | Restricted coin host, signed payment execution, protocol burn and failed-transition recovery |
| `deploy.rs` | Deployment validation, staged payment and program registration |
| `program_call.rs` | Call validation, dispatch, staged settlement and journal assembly |
| `rollback.rs` | State journal rollback and coin journal validation |
| `tests/` | Coin mutation failure injection and program-state/payment rollback regressions |

Public application methods commit a cloned state only after successful execution.
Crate-private `*_in_staged_state` methods require their caller to discard the
staging state on error. Restricted coin-host execution undoes failed mutations
with its coin journal. These boundaries and operation order remain unchanged.

## Coin and asset UTXO ownership

`kernel/src/ledger/utxo.rs` is the shared entry point for `CoinUtxo`, `UtxoSet`,
`AssetShare`, `AssetState` and `AssetJournal`. Implementations live under
`kernel/src/ledger/utxo/`:

| Module | Responsibility |
| --- | --- |
| `coin.rs` | Native coin outputs, checked total value and owner lookup |
| `asset.rs` | Asset state and journal types |
| `asset/encoding.rs` | Canonical asset encoding and index rebuild on decode |
| `asset/index.rs` | Share lookup, owner indexes and input/share checks |
| `asset/operations.rs` | Checked register/mint/transfer/burn and failed-operation recovery |
| `asset/journal.rs` | Sparse operation footprints, quote views, journal merge and rollback |
| `asset/supply.rs` | Root-guarded incremental supply audit and summaries |
| `asset/tests.rs` | Supply, owner indexes, encoding and atomic rollback regressions |

Coin outputs and asset shares share ledger source ownership. `UtxoSet` still
contains native coin outputs, and asset state remains serialized under
`LedgerState.extensions.assets`. Their canonical field order and encodings are
unchanged. Asset metadata and monetary value types remain in `monetary::asset`.
Asset state callers import `ledger::utxo::{AssetState, AssetJournal}` directly.
The old `monetary::asset_state` and `program::system::asset_program::state`
compatibility modules have been removed.

## Application VM modules

`kernel/src/program/vm.rs` retains the common XPVM constants, fuel costs and
public exports. Private modules under `kernel/src/program/vm/` separate the
scalar VM and shared bytecode contracts:

| Module | Responsibility |
| --- | --- |
| `types.rs` | Validated code, execution errors/results and scalar state proposals |
| `requests.rs` | Monetary proposal types and bounded registration decoding |
| `validation.rs` | v1-v3 validation, stack bounds, fuel counting and routing to v4 validation |
| `interpreter.rs` | Deterministic scalar v1-v3 execution without mutable ledger access |
| `tests.rs` | Bytecode compatibility, fuel, deterministic execution and state rollback |

The existing `program::vm` paths remain available. Version routing, serialized
request fields and fuel costs are unchanged. Application v4 execution continues
to require the authenticated kernel context supplied by `vm_app`.

`kernel/src/program/vm_app.rs` retains the XPVM v4 limits, `AppliedVm` receipt
type and existing function exports. Private modules under
`kernel/src/program/vm_app/` own the implementation:

| Module | Responsibility |
| --- | --- |
| `validation.rs` | Bytecode decoding, instruction boundaries, jumps and declared limits |
| `storage.rs` | Bounded canonical storage decoding, storage limits and key checks |
| `execution.rs` | Signed root input, preview staging and execution receipt assembly |
| `engine.rs` | Invocation state, shared fuel/action budgets and authenticated call frames |
| `engine/interpreter.rs` | Typed stack and metered opcode execution |
| `engine/settlement.rs` | Deterministic account selection, monetary effects and merged journals |
| `tests.rs` | VM limits, authorization, settlement, replay and rollback regressions |

Calls share one engine and resource budget. The interpreter delegates monetary
effects to settlement; kernel monetary checks remain authoritative. Preview and
execution use the same engine on disposable or atomic staging state. Instruction
order, fuel charges, account selection and journal assembly are unchanged.

`kernel/src/program/vm_transfer.rs` retains `TransferQuote`, the input limit and
the settlement entry points. Private modules under
`kernel/src/program/vm_transfer/` separate monetary settlement:

| Module | Responsibility |
| --- | --- |
| `coin.rs` | Program-owned coin selection, change outputs and coin journals |
| `asset.rs` | Ordered registration, minting and transfer with merged asset journals |
| `quote.rs` | Read-only quotes through the same settlement routines on cloned state |
| `tests.rs` | Ownership, supply, quote and atomic rollback regressions |

Settlement continues to apply coin effects before asset effects. Registration
precedes minting, so a mint can reference the asset registered in the same call.
The caller owns atomic staging and must discard it if any settlement step fails.
Input ordering, share origins, mint nonces and journal merge order are unchanged.

## What is a program?

A system application is compiled Rust application logic in extension. Its wire
contract lives in kernel. A deployed program is validated XPVM bytecode stored
in `LedgerState.programs`. These are different execution implementations behind
ProgramCall dispatch; system applications have not been converted to bytecode.

`SystemProgramId(u32)` selects MONETARY=0 or VM=2 (route 1 is a legacy asset
decoder alias). `ProgramId` is a 32-byte owner-instance identity, including
stateless signature-policy instances and deployed programs. The VM route carries the deployed hash as its
payload. Asset contract IDs identify asset records, not deployed programs.

`LedgerState.extensions.assets` holds canonical asset records and shares in
kernel-owned state. The name `extensions` does not give extension direct mutable
access to ledger state. Coin UTXOs contain XPQ only.

## Execution boundary

Runtime installs `extension::SystemApplications` through `Ledger::with_applications`,
including after snapshot restoration. The executor capability is not serialized.
A bare production kernel fails closed for application execution until an
executor is installed.

Authorization binds the call and XPQ payment to the chain and signer. Preparation
validates payment and previews state growth. Extension receives restricted hosts:
coin effects must match the signed payment; asset execution must match the signed
instruction. Kernel checks ownership, conservation, nonce and supply, stages the
changes and commits only after validation succeeds. Journals restore prior state
on rollback. The same installed applications serve mempool, execution, replay and
RPC asset state-growth quotes.

XPVM runs in kernel and can propose a scalar program-state effect. Version 2
also proposes fixed coin and asset payouts from the executing program’s own
shares. Version 3 adds program-owned asset registration and minting; kernel binds
authority to the executing program, selects mint nonces and checks lifetime supply.
The kernel settles all effects atomically with caller payment and state changes. See [ProgramCall](PROGRAM_CALL.md) and [XPVM](XPVM.md).


XPVM v4 adds typed calldata, authenticated immediate caller/signing context,
conditional control flow, program-local key/value storage, dynamic monetary
requests, and synchronous calls between deployed programs. The caller program
cannot choose the callee's authenticated caller. Calls share fuel and rollback;
active-frame reentrancy is rejected. These primitives allow new application
bytecode without changing the compiled XPQ/asset applications or node binary.
Kernel monetary validation remains authoritative. See [v4](XPVM.md#application-bytecode-v4).

## Program ownership

The ledger has one ownership variant: `Owner::Program(ProgramId)`. A wallet is
an implicit instance of the system signature policy; its policy, signature scheme, public key and salt determine
its instance ID without deployment or stored account metadata. Deployed instances
use their bytecode policy and cannot spend through the implicit signature path.
See [ownership](OWNERSHIP.md) for resolution, authorization and compatibility.

## Identity and protocol compatibility

ProgramId is the shared identity of signature-policy accounts and deployed
programs, not only a replacement display address. Coin and asset Share IDs are
separate 32-byte domain-separated SHA3-256 identifiers. `SystemProgramId(0)` is
the unified monetary dispatcher route, not an ownership ProgramId; monetary
opcode 1 selects transfer. Account IDs bind policy/scheme/key/salt; deployed IDs
bind deployer/nonce/code hash. An asset contract ID identifies the asset record.

The current chain-spec is 9, database schema is 17, snapshot format is 3 and
wallet file format is 2. Old chain databases are rejected; no migration is
provided. See [ProgramCall compatibility](PROGRAM_CALL.md#storage-and-compatibility).

Application extensibility is bounded by the existing XPVM instructions and hosts.
The VM hashes bytes with XPARQ Raw-domain SHA3-256, while root transaction
signature authorization supports ML-DSA44/65/87 and Pure SLH-DSA SHAKE128s/192s/256s. Other signature or ZK
verifiers are not currently supplied. Other source languages need a compiler
that targets supported XPVM bytecode; arbitrary native, WASM, EVM or Cairo
binaries are not accepted. Adding native primitives or changing consensus
semantics requires updating nodes; deploying new supported bytecode does not.

Protocol SHA3-256, ML-DSA SHAKE and SLH-DSA SHAKE share the vendored Keccak
implementation. SLH uses the same `shake` crate as ML-DSA. Its optional SHA2/HMAC
backend is gated by `crypto/slh-sha2-benchmark` and adds no account scheme.

# Shared ledger payloads

Ledger copies used by preview, validation, rollback and reorganization retain
private mutable state while sharing immutable historical payload allocations.
This reduces repeated bytecode and block-body copies without changing canonical
block, operation, registry or snapshot bytes.

## Implementation

- `Block.body` is an `Arc<Body>`. Cloning a block copies its header/height and shares
  the emission/operation payload. `Block::body_mut` uses `Arc::make_mut` to isolate
  a writer; `push_operation` uses this path before refreshing commitments.
- `DeployProgram.code` and `ProgramRecord.code` are `Arc<Vec<u8>>`. Execution clones
  and registry records share the deployment's code allocation. Mutable fields such
  as program state values, coin state and journal/map entries remain private in
  cloned state. Copying or rolling back a ledger does not deep-copy historical code.
- Borsh's `rc` feature serializes the referenced value, not pointer identity or
  reference counts. Both program types keep their explicit bounded code decoder;
  block decoding still applies its existing bounded operation decoder.
- Program-code hashing borrows the input slice instead of creating a temporary
  owned copy before canonical serialization. Slice and Vec encodings are identical.

No unsafe sharing or global code-interning cache is introduced. Last-owner drop
releases a shared allocation normally. Caller mutations through `Arc::make_mut`
create a private allocation when necessary; they cannot mutate another ledger's
shared code/body. Consensus validates the resulting contents and commitments as
before. State staging and the commit-after-validation behavior remain intact.

## Rust source migration

Canonical wire/storage formats and wallet CLI flows are unchanged. Direct Rust
struct users should set a code field with `code: code.into()` when starting with a
Vec. To mutate a cloned block's body, call `block.body_mut()` and then refresh its
commitments as appropriate. To mutate shared code in a local construction or test,
use `Arc::make_mut(&mut deploy.code)`. All repository callers/examples are updated.

## Verification and limits

The compatibility tests compare shared payloads against owned Vec/struct encoding,
check program-code hashes against the previous owned-input implementation, decode
legacy bytes and validate registry restoration. They also exercise shared allocation
identity, private body/code mutation and independent registry/record changes.
Kernel, wallet, node, snapshot, native transport and network regressions check the
existing failure/rollback invariants. The large valid-body experiment is repeated
without other XPARQ regression suites running at the same time.

For measured results, see [the repeated resource experiment](audit/ledger-memory/README.md).
Sampled target peak RSS decreased from 423.16 to 233.96 MiB in baseline and
428.48 to 236.40 MiB with four flood identities, approximately 45% in this fixture.
Source peaks decreased by approximately 29%. These are single-run observations.
Commands are listed in [memory verification](audit/ledger-memory-verification.txt).
The preceding measurements remain in [the original resource report](audit/litep2p-stress/README.md).

This is allocation sharing, not bounded historical memory. The node now keeps historical bodies on disk with a bounded resident cache;
see [historical body storage](HISTORICAL_BODY_CACHE.md). UTXO/program state, header
history and rollback journals still reside in RAM. Independently
decoded snapshots can allocate code separately from decoded historical bodies.
Canonical serialization/state-root buffers, database caches and retained allocator
capacity also remain. Production journal retention is now bounded to 256 blocks
with scratch recovery and disk-backed historical receipts; see
[journal pruning](JOURNAL_PRUNING.md). A disk-backed active-state store and
streaming state commitments remain separate work.

Scratch recovery beyond the journal is now implemented; see
[recovery behavior and limits](SCRATCH_RECOVERY.md). Disk-backed UTXO state
remains separate work.

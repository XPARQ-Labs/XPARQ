# Historical bodies on disk

The node keeps canonical block bodies in the existing redb `canonical_blocks`
table and retains a recent-body cache in the ledger. All canonical headers remain
available independently of that cache. This changes storage access and allocation,
not consensus, canonical block encoding, genesis identity or the database schema.

## Resident cache and reads

The node cache targets at most 16 MiB of logical canonical block encodings and
128 recent entries. Genesis and the current tip are pinned; pinned entries can
exceed those limits, especially if a caller selects a smaller test budget.
These are cache limits, not a total RSS limit or exact heap-accounting measurement.

`Chain::headers` visits the complete header history. `Chain::blocks` and
`Chain::block` visit only resident bodies after explicit eviction. Standalone kernel
ledgers retain their bodies by default. Node callers use `canonical_block` to read
a resident body or fetch one historical body from redb. The body must match the
height and header in the caller's pinned ledger, and authenticate its Merkle commitment after bounded decoding. These bodies
already passed full validation when admitted to the local chain; serving them does
not repeat VM/operation validity checks. Peer blocks and full replay retain their
full validation paths.
A read overlapping a canonical replacement fails if the stored branch no longer
matches that pinned ledger; it cannot return another branch's body as canonical.

Header locators, header response chunks, work checkpoints and difficulty adjustment
use headers. Historical block RPC, explorer receipts, address activities, body
requests, index rebuilds and canonical persistence can read bodies from disk.
Index rebuilding and startup replay process one encoded body at a time.

`CanonicalBodyReader` pins a redb read transaction. The iterator observes a stable
canonical generation during concurrent commits. It holds its database handle for
its lifetime; a weak live-handle registry allows reopening another known directory
without losing access to an outstanding reader, while avoiding permanent retention
of every database directory. It rejects a missing height,
empty entry or oversized body and stops after an error. Nothing deletes archival
bodies from the database.

## Validation, snapshots and reorganization

Full replay applies consensus validation to every streamed block and trims the
resident cache after each successful step. Compact local snapshot restoration
streams the prefix, validates structure, linkage, difficulty and PoW, checks
journal coverage and state invariants, and recomputes the state root against the
boundary header. The suffix is then fully executed. A bad snapshot falls back to
full replay; legacy snapshot caches also fall back to full replay. Wallet files,
canonical database bodies and snapshot version 3 encodings remain unchanged.

Snapshots remain local caches of state previously fully validated by this node.
This loader does not authorize peer-supplied snapshots or prove historical
transaction validity from header PoW alone. The legacy kernel snapshot API retains
its existing contract; the bounded streaming restoration path performs additional
PoW checks.

For reorganization, missing resident bodies are rehydrated from the stored
canonical branch as needed. Rollback state-root checks can use the parent header.
The candidate ledger remains private. The current canonical work is checked again
under the mutation lock, and body/state validation completes before the existing
atomic database replacement and cache publication. A missing/corrupt local body
is reported as a storage/recovery problem, not a new invalid-chain rule.

## Remaining work

This is the historical-body stage of the memory/storage plan. The active UTXO and
program state, header history and recent rollback journals are still held in RAM.
[Production journal retention](JOURNAL_PRUNING.md) now keeps 256 block journals
and archives historical burn receipts on disk. Shallow rollback uses retained journals;
[scratch recovery](SCRATCH_RECOVERY.md) now handles missing journals by restoring
a local snapshot or replaying genesis and publishing a fully validated branch
atomically.
Private downloaded candidate ledgers can retain their new branch bodies until
commit. Snapshot serialization, allocator capacity, database cache and concurrent
readers also contribute to process RSS.

Snapshot journal suffix validation and historical receipt lookup now support
pruning. A disk-backed active-state store and bounded cache are separate work. No finalized epoch, irreversible
checkpoint, remote snapshot trust policy or consensus pruning rule is introduced.

Verification and measured resources: [audit record](audit/disk-body-cache-verification.txt).

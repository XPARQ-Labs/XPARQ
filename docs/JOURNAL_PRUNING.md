# Production rollback journal retention

The node runtime retains the latest 256 block journals. This is a local memory
policy, not consensus or finality. The kernel exposes journal metadata and an
explicit pruning primitive; it does not choose a production retention limit.
Changing the local retention window does not change block or chain validity.

Before deleting any expired journals, the runtime archives their per-operation
protocol burn receipts in the existing redb auxiliary table. Receipts are keyed
by block hash, so a reorg cannot substitute a receipt from another branch at the
same height. The explorer checks the pinned canonical header and reads recent
receipts from journals or historical receipts from disk. Bodies remain on disk.
Empty-operation blocks need no receipt record. A missing or malformed archived
receipt is a local data error; the explorer does not invent a zero burn value.

If an archive write or body read fails, pruning is deferred and all journals
remain available. Valid execution state can still be published. Under healthy
storage, retention applies during startup replay, sync, scratch recovery and
canonical cache publication. Snapshot state and chain commitments are unchanged.

Compact snapshots now accept a contiguous suffix of rollback journals ending at
the snapshot tip. Each retained block must have exactly the expected journals;
holes, unrelated keys and empty coverage are rejected. Old full-journal snapshots
remain readable within the same chain identity. Journal pruning does not change
snapshot version 3 or storage encoding. The current database schema is 17;
older chain schemas are rejected.
Older clients that require full journal coverage fall back to genesis replay when
they encounter a pruned snapshot. Wallet and block formats are unchanged.

A shallow reorg uses available journals. A deeper preferred fork enters
[scratch recovery](SCRATCH_RECOVERY.md), which restores a snapshot at or below
the common ancestor or replays genesis, validates the candidate, and publishes
its canonical log and final state snapshot atomically. Local mining may continue
while replay runs: a concurrent append does not cancel recovery if the candidate
remains preferred. A changed common ancestor requires a fresh sync session.
Recovery also copies
historical receipt caches from scratch to the active store before publication.
These hash-keyed caches may contain receipts for discarded branches; canonical
membership is checked separately. They never authorize a transaction or select
a fork, and orphan receipt cache rows are not automatically deleted.

The 256-block window bounds journal count, not process RSS or journal bytes.
Large recent transactions can still require substantial undo data. Active UTXO
state, program state and headers remain in RAM. Loading an older full-journal
snapshot may temporarily exceed the new window before archival and pruning.
The runtime retention helper supports differing local windows without changing
consensus; no CLI retention option is introduced in this change.

Commands and results: [verification record](audit/journal-pruning-verification.txt).

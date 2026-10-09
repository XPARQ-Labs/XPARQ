# Recovery beyond the rollback journal

A missing rollback journal is missing local optimization data. It does not
invalidate a competing chain and does not introduce finality or an epoch genesis.
Normal reorgs still use the journal fast path.

When a preferred branch cannot be rolled back using available journals:

1. Check the active state root against its tip commitment, then release the state
   mutation lock. Only one scratch recovery runs at a time.
2. Independently verify candidate headers, PoW, difficulty and cumulative work.
   The validated work and weight must match the sync session's claimed values.
3. Restore a locally persisted snapshot at or below the common ancestor. Its
   checksum, network identity, header history, journal coverage and state root
   must validate. Every restored header must match the captured canonical branch.
   Unusable snapshots fall back to genesis replay. No peer snapshot is trusted.
4. Stream canonical prefix bodies into an isolated redb database and replay the
   suffix after the snapshot. Check every prefix body against the captured header.
   Fully execute every candidate block, persisting its body before evicting it
   from the bounded body cache. Historical bodies remain available on disk.
   Persist the fully validated execution state as a local snapshot in scratch.
5. Acquire the mutation lock again. If the common ancestor changed, defer and
   sync against fresh history. Concurrent appends above that ancestor are allowed;
   validate the active tip root and recheck preference against its latest work.
   Reconcile disconnected and
   pending operations, and atomically replace canonical bodies, indexes, mempool
   and the recovered state snapshot in one redb transaction, dropping snapshots
   from the replaced branch.
6. Publish the validated in-memory ledger only after storage commits. Delete the
   owned scratch directory on success or failure. An interrupted process may
   leave a scratch directory; startup never treats it as canonical state.

A bounded cache remembers up to 64 consensus-invalid block commitments, including
when a later candidate extends the same invalid block. Corrupt bodies that do not
match their Merkle commitment and local storage/download failures do not enter
this cache. Different branches at the same fork height remain eligible.

The active and scratch execution states and rollback journals still reside in
RAM. The scratch database stores bodies, indexes and the final state snapshot; this change does not make
UTXOs disk-backed. [Production journal pruning](JOURNAL_PRUNING.md) retains
256 block journals and archives explorer burn receipts on disk. The devnet-only journal discard method exists to
exercise recovery under an expired-journal condition.

Canonical storage schema, snapshot encoding, block encoding, chain specification
and wallet formats are unchanged. After a crash during publication, redb exposes
the old or new complete canonical log; startup reconstructs execution state from
that log and validated local snapshots.

Verification covers journal expiry, genesis fallback, snapshot selection below
the fork, partial stream failure, uncommitted body corruption, mined headers with
invalid execution roots, repeated invalid candidates, concurrent tip movement,
scratch cleanup, canonical index publication and restart replay.

Commands and results: [verification record](audit/scratch-recovery-verification.txt).

# Local restart validation

Normal restart can reuse a locally persisted validation checkpoint. The node
still streams every body through the snapshot height, checks its encoding and
structure, reconstructs chain linkage, restores bounded body caches, and audits
snapshot supply, registry, root and journal coverage. It skips historical
Argon2id only after matching the exact encoded prefix to its checkpoint. Tail
blocks are admitted and executed normally.

The checkpoint lives in the additive `snapshot_validation_checkpoints` redb
table. It records validation version 1, genesis hash, chain-spec hash, snapshot
height, tip hash, SHA3 fingerprint of the stored snapshot bytes, and a chained
fingerprint of every encoded body from genesis through that height. Its version
must be bumped if admission rules change without a chain-spec change. These are
local cache fingerprints, not consensus hashes or authenticated signatures.

Snapshot publication uses one write transaction. Before committing, it compares
each stored body's decoded header and height to the admitted in-memory ledger,
then computes the prefix digest inside that same transaction. A mismatch aborts
the write. Checkpoint lookup uses the body reader's pinned generation. Snapshot
hash binding rejects a snapshot read from a different generation. Reorgs discard
checkpoints for the replaced branch; publishing a recovery snapshot at a height
invalidates any earlier checkpoint there. Plain test snapshot writes cannot
preserve an old checkpoint, and retention deletes both records together.

If no checkpoint matches, normal startup falls back to full genesis execution
and PoW verification. This also migrates older databases: successful replay
publishes a new snapshot/checkpoint even below the periodic snapshot interval.
Successful tail replay refreshes the checkpoint at the resulting tip. A failed
checkpoint write leaves the validated ledger usable, but a later restart may
need to repeat verification. A history digest mismatch rejects that snapshot;
an earlier certified snapshot may still be used, with its tail validated again.

Recovery calls `load_streamed_through`, which deliberately ignores the fast-path
checkpoint and retains historical PoW checks. Recovery still uses trusted local
snapshot state for the prefix, then executes subsequent blocks. For a full
execution audit, including data imported from elsewhere, run:

```bash
node check /path/to/database --full
```

This bypasses snapshot restoration and replays from genesis. A checkpoint is not
a defense against a party that can replace both the database and checkpoint.
Normal startup assumes the node owns and trusts its local persisted validation
records. Copying a database does not establish that trust.

## Measurement

Successful snapshot loads report the selected mode (`trusted-local` or
`verify-pow`), block count, PoW-check count, checksum/snapshot decode time,
history time (I/O, decoding, fingerprint and chain reconstruction, excluding
PoW), PoW time, supply audit, registry checks, state root, and total time.
`check --full` reports total full-replay elapsed time.

The integration fixture compares identical one-block histories using freshly
decoded snapshots, so memoized roots do not hide root/audit work. An initial
measurement was about 2.48 seconds for the single historical PoW check, versus
0.05 milliseconds for the in-memory trusted history stage. The fixture is tiny
and cache-warm; these values do not predict end-to-end large-database restart
times. Restart still reads the complete prefix and reconstructs indexes;
snapshot publication also scans that prefix under the write transaction.

## Regression coverage

Tests exercise atomic checkpoint/snapshot publication, rejected history changes
without partial writes, pinned generations, plain overwrite invalidation,
recovery publication invalidation, missing checkpoint fallback, equivalent
full/trusted restored ledgers, zero historical PoW on normal process restart,
structurally valid body tampering, and explicit full replay despite an existing
checkpoint. Existing snapshot, rollback, storage and reorg tests remain active.

# Validation and synchronization CPU costs

Block application no longer clones the complete `Chain` to append one block.
Transaction execution remains staged privately. Weight, state root and monetary
checks finish before commit. `Chain::insert_block` completes all fallible checks
before changing its maps or tip, so rejected blocks leave the ledger unchanged.

The private block execution state is now cloned once per block and reused across
its transactions. Prepared calls and deployments use internal staging methods
that do not clone that state again. A failure discards the entire private block
state, including successful earlier transactions. Public single-transaction
methods retain an isolated state copy and commit only on success.

Asset operations capture their accounting record, consumed share IDs and all
possible output IDs in a sparse rollback journal. They no longer clone or diff
the global asset maps. Errors restore the captured entries. The restricted asset
host also rolls back an operation if its application returns an error or unwinds
after mutation. Successful journals retain the historical sorted encoding and
include changed entries only.

Asset state-growth quotes copy only that operation's footprint, including existing
output IDs for collision checks, and use the journal's exact canonical size delta.
Coin-only quotes return before making any extension-state copy. This preserves
the existing burn calculation while avoiding full asset-map serialization.

Program records share storage maps through `Arc`, as they already share code.
Cloning ledger state for a VM quote, block or branch copies references instead
of every program's storage keys and values. `set_storage` uses copy-on-write:
the first actual write detaches only that program's map when it is shared.
Repeated writes to the private map need no further copy. Replacing a value with
the same bytes or deleting a missing key keeps the map shared. A write can still
copy up to the program's bounded storage size; this is not an entry-level overlay.
Serialization writes the same map bytes, so storage burn, state roots and
snapshot encoding do not change.

Coin UTXO and asset tables use [structurally shared ordered maps](STATE_MAP.md).
A ledger clone shares roots for coin UTXOs, asset records, asset shares and owner
indexes. Writes detach only AVL paths, including nested owner/share indexes;
the first monetary write no longer copies a whole table or owner's share set.
An asset transfer keeps the accounting-record root shared. Rejected coin operations
validate before detaching, and asset rollback skips entries whose value has not
changed. Encoding, ordering, supply checks, state roots and burn are unchanged;
general VM previews retain the complete collision and ownership view.

The trees have logarithmic depth and no overlay layers to compact. Exclusive
branches are updated in place; shared branches are copied only as needed. This
adds per-node allocation and pointer traversal compared with flat BTreeMap tables,
and full state scans and serialization remain linear. Program storage continues
to use table-level copy-on-write as described above.

[State-root memoization](STATE_ROOT_CACHE.md) avoids repeating serialization and
SHA3 hashing for the same canonical state. Its key retains monetary, program and
extension tree roots plus coin accounting values. Mutations detach roots, making
old keys fail automatically. Program registry and deployment-index clones now
share roots too. New or changed states still require the full historical hash;
this does not introduce a Merkle commitment or change the consensus root.

[Incremental supply validation](SUPPLY_AUDIT_CACHE.md) establishes per-asset totals
with a full audit, then updates them from sparse kernel journals. Normal checks
validate affected assets; unchanged assets remain covered by the audited baseline.
Root guards force a full scan for stale summaries or untracked changes. Coin
accounting is checked every time, and snapshot restore forces deep asset and coin
audits. Summaries are excluded from canonical encoding and state equality.



Synchronization, snapshot restoration, startup body replay and scratch recovery
reuse one Argon2 working buffer per batch through the shared admission checks.
Body replay uses `apply_block_with_pow_memory`; snapshot restoration uses
`validate_block_for_apply_with_memory`. Each block still
gets full structural, linkage, difficulty, PoW, authorization and ledger checks.
Header verification and body application continue to verify PoW independently.
The buffer is allocated lazily in sync/replay/restore and released after the batch;
recovery also reuses its header-validation buffer for body application.

The kernel rejects buffers whose size differs from the consensus parameter.
Argon2 remains 128 MiB, one iteration, one lane. Hash outputs, consensus rules,
chain-spec identity and database encoding are unchanged by these optimizations.

## Reproduce the measurements

The latest first-write measurements and command are in [state maps](STATE_MAP.md).
They compare whole-table copy-on-write with shared paths on 20,000 and 100,000
UTXOs, including a large single-owner index. Current owner lookup measurements
and scan costs are in [owner indexes](OWNER_INDEX.md).

```bash
cargo test -p kernel --release --locked --offline --test cpu_validation \
  benchmark_chain_commit_and_pow_allocation -- --ignored --nocapture

cargo test -p kernel --release --lib --locked --offline \
  benchmark_asset_clone_and_sparse_journal -- --ignored --nocapture
```

Earlier release runs on an Intel Core i7-8550U produced:

| Workload | Previous allocation/copy path | Optimized path |
| --- | ---: | ---: |
| 128 chain appends, 1,000 historical headers | 6.184 ms | 0.292 ms |
| 128 chain appends, 20,000 historical headers | 166.677 ms | 0.358 ms |
| Eight Argon2 hashes, fresh versus reused buffer | 1,185.100 ms | 646.417 ms |
| 128 asset mints with 20,000 existing shares | 560.771 ms | 0.383 ms |

These are elapsed-time microbenchmarks, not end-to-end synchronization timings
or process CPU measurements. The chain fixture tests bookkeeping only and keeps
64 recent bodies plus genesis; its blocks are not mined. Both chain paths must
produce exactly equal chains. Both hashing paths must produce equal hashes for
the same headers. The hash comparison allocates the reusable buffer before its
timed loop, as a batch would; first-allocation cost still exists. Order, allocator
warmup and machine load can affect these single-run results.

The earlier asset measurement used historical clone-and-global-diff as its
baseline. After the map change, the live test oracle explicitly reconstructs full
maps before executing and diffing; its current timings include that reconstruction. It excludes baseline payload decoding; the optimized path includes
decoding. It checks identical final state and journals. It does not measure
signatures, block execution, state roots or synchronization as a whole.

## Canonical size checks without payload buffers

Program-call admission and deployment burn quotes now count canonical bytes using
borrowed operation views, instead of cloning the authorized transaction and
serializing it into a Vec solely to read its length. The borrowed enum retains
the owned operation's variant order and payload encoding. Block operation-size
checks also use the counting writer. Deployment registry growth is counted from
the new key/record pair without allocating its canonical buffer.

Wallet fee-convergence loops also count canonical lengths directly. Deployment
sizing borrows the signed operation; transfer sizing counts the existing envelope.
These loops still sign their candidate transactions and obtain deploy burn quotes
from the node. Only size-only buffer allocation and the deploy sizing clone are
removed; signing, RPC calls and submission bytes remain required. Wallet tests
compare fees and burn with full encoding at independent rates, verify signatures
and reject arithmetic overflow.

The existing limit comparisons, archival-byte burn, state-growth burn and error
mapping remain unchanged. Serialization needed for hashes, wire messages or
persistence still produces bytes; these changes concern size-only checks.
Tests compare both borrowed variants byte-for-byte with owned encoding, including
79/256-input calls, large payloads and values beyond the operation-size limit.
Existing deployment quote tests retain the full-serialization growth/burn oracle,
and frozen vectors verify integrated consensus outputs.

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_borrowed_operation_size -- --ignored --nocapture
```

A release run on the Intel Core i7-8550U measured 1,000 size calculations:

| Fixture | Clone and Vec encoding | Borrowed counting |
| --- | ---: | ---: |
| Deploy, 69,428 encoded bytes | 2.364 ms | 0.119 ms |
| Program call, 73,505 bytes and 256 inputs | 4.776 ms | 1.408 ms |

Each fixture carries a 64 KiB code/payload. Construction and expected-size
calculation happen outside timing; both loops check identical sizes. These are
single-run elapsed-time microbenchmarks of sizing, not complete validation or
sync throughput. Structured input entries still need traversal by the serializer.

## Mempool serialization measurement

The [mempool serialization benchmark](MEMPOOL_SERIALIZATION.md) measures outer
admission bookkeeping separately from execution and storage. Duplicate lookup
previously recomputed IDs of every pending operation, while size checks and
persistence repeatedly encoded the list. Admission now retains canonical bytes,
IDs and relay lengths in a bounded cache, uses an ID index for duplicates, and
writes borrowed bytes after full validation. Cache reads compare a fresh committed
DB snapshot; other persistence paths and signature/VM execution retain their
existing behavior. The linked notes describe safety, memory cost and benchmarks.

## Verification and remaining costs

`kernel/tests/cpu_validation.rs` checks fresh/reused hash equality after switching
headers, identical ledger bytes through both admission paths, invalid PoW and
wrong-sized buffer rejection, and atomic failures for invalid state roots and
chain insertions. It also compares restored snapshot bytes with the validated
ledger and rejects a historical block with insufficient PoW. Existing workspace
tests cover rollback, recovery, snapshots,
transaction authorization and network synchronization.

Generated asset lifecycle tests additionally compare sparse execution with the
full-copy-and-diff oracle: resulting state, serialized journals, full
serialized size deltas and sparse quotes must agree. A collision on the second
output tests rollback after inputs have been consumed and the first output
created. Host tests cover errors, repeated operations, missing operations and
application panic after mutation.

Ledger state is still cloned once for staged block execution and for public
single-transaction operations; the runtime still clones a
ledger for isolated canonical mutations or branch staging. State-root calculation,
deep asset audits, journal persistence and transaction execution remain costs
to profile separately. General VM previews and rollback share monetary roots
and detach affected paths when writing. Program registry maps and deployment
indexes now share roots too; records share code and storage. Coin and asset tests
check root sharing, rejected operations, original-state isolation, rollback and historical encoding.
Registry tests verify sharing, isolation after updates/deletions, no-op writes and
historical record encoding; VM and snapshot tests cover execution and restore
through these records. Root-cache tests compare all canonical mutation categories
and concurrent forks with the uncached historical hash. Supply-cache tests cover
changed invalid data, overflow, fork interleaving, rollback, fresh coin checks and
a deep snapshot audit that bypasses even a deliberately forged internal memo.
The [owner indexes](OWNER_INDEX.md) now reduce balance and input lookup scans.
Cold hashing still scans the full state, but now streams through a 64 KiB buffer
instead of allocating the full canonical payload; the historical root is unchanged.
The [state-root notes](STATE_ROOT_CACHE.md) include a cold-hash benchmark. Merkle commitments and a replacement
database layout are not implemented.


The recorded benchmarks above predate the chain-spec 7 salted-account reset.
Current authorization proofs add a fixed 32-byte salt; rerunning the benchmarks
therefore reports larger encoded transaction sizes. The cache/counting mechanisms
and benchmark scopes are unchanged.

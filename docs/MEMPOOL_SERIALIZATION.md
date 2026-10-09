# Repeated serialization in mempool admission

This measurement covers serialization and hashing around program-call admission.
The first benchmark below records the original outer admission path. A retained
cache is now implemented; its behavior and separate benchmark follow below.
The fixture uses ML-DSA-44-sized authorization data, one coin input and one output,
with synthetic VM payloads. The fixtures are not valid executable calls: no ledger
validation or signature verification is performed by this microbenchmark.

## Code path and repetition

For a new, nonduplicate program call entering a mempool with N existing operations,
the outer admission bookkeeping serializes payloads as follows:

| Stage | Serializations |
| --- | ---: |
| Legacy transaction size and transaction ID | 2 |
| New operation size and operation ID | 2 |
| Existing operation IDs for duplicate detection | N |
| Block-size checks across the resulting pending list | N + 1 |
| Relay sizes across the resulting pending list | N + 1 |
| Encoding the pending list for persistence | N + 1 |
| Total in these stages | 7 + 4N |

These counts are derived from the current code path, rather than instrumented
production counters. Execution, authorization commitments, signature verification,
VM work and storage I/O can add further work and are excluded. The benchmark calls
the actual ID, relay-size and persistence-encoding helpers, and reproduces their
surrounding size checks without applying transactions or writing a database.

Both legacy transaction ID and operation ID require serialization plus SHA3. They
use different framing/domain separation, so an operation ID cannot simply replace
a legacy transaction ID. Relay sizing currently clones the program call into its
legacy envelope and serializes it solely to obtain length.

Sequential admission of M distinct calls starting from an empty mempool performs
2M² + 5M serializations in these outer stages, assuming all calls are accepted and
none are removed. This does not include revalidation execution costs.

## Release benchmark

```bash
cargo test -p node --bin node --release --locked --offline \
  benchmark_mempool_repeated_serialization -- --ignored --nocapture
```

Single release run on an Intel Core i7-8550U. Each row performs eight repetitions
of the modeled admission bookkeeping; the table reports their average elapsed
time per admission. Fixture construction and reference hashes are outside timing.
Every iteration checks expected IDs, sizes and persistence output lengths.

| Existing operations | Payload per call | Encoded operation | Serializations per admission | Encoded bytes across passes | Average time |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 4 KiB | 7,985 B | 7 | 55,895 B | 0.105 ms |
| 64 | 4 KiB | 7,985 B | 263 | 2,100,055 B | 3.535 ms |
| 512 | 4 KiB | 7,985 B | 2,055 | 16,409,175 B | 27.624 ms |
| 0 | 64 KiB | 69,425 B | 7 | 485,975 B | 0.788 ms |
| 64 | 64 KiB | 69,425 B | 263 | 18,258,775 B | 29.451 ms |
| 512 | 64 KiB | 69,425 B | 2,055 | 142,668,375 B | 243.538 ms |

For 512 existing 64 KiB calls, the eight repetitions break down as follows:

| Stage | Elapsed time | Share |
| --- | ---: | ---: |
| Legacy size and ID of new transaction | 3.438 ms | 0.2% |
| New operation size/ID and existing duplicate IDs | 1,598.779 ms | 82.1% |
| Block-size checks | 28.647 ms | 1.5% |
| Relay-size checks | 44.547 ms | 2.3% |
| Persistence encoding | 272.897 ms | 14.0% |

The encoded-byte total is cumulative data produced across these passes, not peak
memory. Timing includes SHA3 in ID stages and cloning in relay sizing. This is not
an end-to-end admission benchmark or a live production CPU profile. Ledger replay,
verification, database latency, synchronization and gossip are not measured;
single-run timings are sensitive to machine load and allocation behavior.

## Optimization selected from the baseline

Prioritize retaining computed operation IDs and canonical bytes for pending entries
across admissions, then use an ID index for duplicate lookup. A cache local to one
request would still hash every existing operation on the next admission. Cached
bytes can also supply sizes and be reused for persistence; preserve distinct
legacy and operation IDs where needed.

The current database stores ordered raw operation bytes, without an operation-ID
index. A retained cache must follow successful persistence, removals, reconciliation,
reorg and restart recovery. It adds memory, so it should respect existing mempool
count/byte bounds and share byte buffers where possible. Replacing size-only Vec
encoding with counting alone is a smaller change, but the measured dominant cost
is repeated ID hashing. The retained cache described below implements this approach for admission.


## Retained admission cache

The node now retains one database's pending entries in a bounded shared cache.
Each entry owns its decoded operation, canonical bytes, operation ID and relay
length; a separate ID set supports duplicate membership lookup. Admission stages
share existing entry references and create only the new entry. Full transaction
validation is still performed against a privately staged ledger on every admission.
The cache never represents signature validity or execution validity.

Every cache load still reads a committed mempool snapshot from redb and compares
its ordered bytes exactly with the cached entries. A matching path and snapshot
reuses the entry set; different bytes, count or order rebuild the cache. Thus
mining, reconciliation, reorg, recovery, direct storage writes and database-path
changes cannot use stale membership. A cache slot evicted by another path can
cause extra work without changing results. Invalid stored bytes still fail decode;
noncanonical input encoding retains historical decoding behavior and is not cached.

A successful admission writes borrowed canonical byte slices into one redb
transaction. It publishes the candidate cache only after commit succeeds. A failed
validation or write leaves the previous cache untouched; committed database bytes
remain authoritative. Other persistence paths continue using their existing
encoding functions and are detected by snapshot matching on the next read. No
schema, transaction encoding or consensus changes are required.

Legacy transaction IDs and operation IDs remain distinct. Operation IDs are
hashed from the cached operation encoding with the existing Operation domain.
Legacy relay lengths are counted through their own borrowed envelope. Tests
compare both IDs and framing with the original helpers.

The cache respects the existing 1,024-entry and 64 MiB encoded-mempool limits.
Retaining canonical bytes adds up to 64 MiB of payload storage alongside decoded
operations and metadata. Snapshots and staging reads can allocate temporary data.
This optimization does not remove database reads, exact byte comparisons, full
signature/VM revalidation or re-encoding in the other persistence paths.

```bash
cargo test -p node --bin node --release --locked --offline \
  benchmark_retained_pending_cache -- --ignored --nocapture
```

A single release run on the Intel Core i7-8550U with 512 synthetic deploy entries,
each with 64 KiB bytecode, measured eight repetitions:

| Path | Elapsed time |
| --- | ---: |
| Read raw DB bytes, decode, recompute duplicate IDs, encode pending list | 3,927.108 ms |
| Read raw DB bytes, match retained cache, ID-set lookup, borrow pending bytes | 138.379 ms |

The fixture's matching ID is the final entry, so the old lookup hashes every
entry. Cache priming and fixture writes are outside timing. The benchmark asserts
that every warm read reuses the same pool and finds the expected ID. Both paths
read the actual database; neither verifies signatures, executes the synthetic
programs or commits the output. These timings cover bookkeeping and preparation,
not complete admission or synchronization. They are a separate fixture/run from
the original program-call benchmark above.

Tests also replace/reorder mempool bytes through storage directly, inject corrupt
bytes, clear the pool and simulate a failed write. The committed pool stays
correct, candidates are isolated, and legacy ID/operation ID separation is checked.
Workspace mining, gossip, snapshot recovery and reorg tests verify integration.


The recorded benchmarks above predate the chain-spec 7 salted-account reset.
Current authorization proofs add a fixed 32-byte salt; rerunning the benchmarks
therefore reports larger encoded transaction sizes. The cache/counting mechanisms
and benchmark scopes are unchanged.

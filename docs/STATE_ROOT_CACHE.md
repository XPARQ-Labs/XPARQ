# Compatible state-root memoization

The protocol root remains SHA3-256 over the existing domain tag, encoded payload
length and canonical Borsh bytes of UTXOs, coin accounting, programs and extensions.
The empty-state sentinel remains zero. An incremental Merkle root would produce a
different commitment and require a protocol change; this optimization keeps the
existing root and avoids repeated work for an unchanged state instead.

## Cache key and mutation safety

Each ledger state carries a derived cache with one entry. A cached hash is returned
only when all canonical components match its retained key:

- The coin UTXO tree root and serialized total-value cache.
- The mined and burned coin accounting values.
- The program registry tree root.
- The asset record and share roots in extension state.

Program registries and owner/nonce deployment indexes now use StateMap, as coin
and asset tables do. Cloning a registry shares roots, code and program storage;
mutating a record copies affected paths. Scalar/storage no-op writes preserve the
registry root. The cache retains actual trees rather than bare pointer addresses:
retention prevents allocation-address reuse and makes canonical mutations detach
shared roots. Thus a write cannot modify cached content in place. Coin accounting
is compared by value because it is directly mutable. There are no manual dirty
flags to maintain across mutation or rollback paths.

Cache identity checks exhaustively destructure state/component types so future
fields require their handling to be considered. Derived owner and deployment
indexes are omitted from canonical bytes and do not determine cached hashes.
Applications cannot inject hashes or keys: the cache's contents and write methods
are internal to the kernel.

A state clone shares the cache slot. Forks may replace one another's entry, but
every lookup checks its own key. An interleaved fork can cause a cache miss rather
than reuse a different state's hash. Cache locks are held only for lookup and
replacement; serialization and hashing happen outside the lock. Concurrent misses
can perform duplicate work, which does not affect results.

## Encoding, equality and restore

Cache metadata is skipped by Borsh and excluded from state equality. Snapshots
therefore retain their historical bytes and roots; restore starts with an empty
cache and computes the first root normally. Transaction format, burn, chain-spec
version and database schema are unchanged. Rollback and component replacement
are covered by root identity/value checks, including direct changes to the public
coin accounting fields. A replaced component that decodes to the same bytes can
conservatively miss the cache and still produces the same hash.

## Verification

Tests compare cached results against the uncached canonical-byte/hash reference
through coin mutations and accounting changes; asset register, mint, transfer,
burn and reverse journals; deploy, scalar/storage changes, no-op writes, removal
and restore. Tests also interleave cloned states, read forks concurrently and
compare historical encoding. Frozen consensus vectors and existing block-root
rejection, snapshot, replay, restart, synchronization and reorg tests cover the
integrated admission path.

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_repeated_state_root_cache -- --ignored --nocapture
```

This benchmark builds 100,000 coin UTXOs and compares 32 full canonical
serialization/hash calls with 32 cached root calls. Fixture construction and cache
priming are outside timed loops. Each root must equal the uncached reference;
changing coin accounting afterward must miss the cache and produce its new root.
It measures warm repeated-root checks, not new-block hashing or end-to-end sync.

A release run on an Intel Core i7-8550U after workspace tests finished measured
**1,377.720 ms** for 32 full serialization/hash calls and **0.002 ms** for 32
cache hits. This single-run elapsed-time microbenchmark is sensitive to machine
load and timer resolution, especially for the very short cached loop.

## Bounded buffer on cache misses

Cold hashing streams the same canonical serialization through a 64 KiB buffer
into SHA3 instead of constructing a Vec containing the entire ledger. The domain
tag and u64 little-endian payload length stay unchanged. The hashing writer rejects
both shorter and longer streams than the declared length, and serialization errors
never produce a cached root.

Coin UTXOs and asset shares have fixed encoded entry widths. Their encoded lengths
are calculated from map counts and a serialized sample of the entry type, without
traversing those tables a second time. Asset metadata and program records use a
counting writer; it counts code, strings and storage payload lengths without copying
their contents. Variable record and storage entries still need traversal. Checked
arithmetic and the Borsh u32 map-count limit reject unrepresentable lengths.

Tests compare counted lengths and streamed roots with the historical Vec reference
across the existing coin, asset, program, rollback and restore scenarios. Crypto
tests cover buffer boundaries, large payloads, wrong lengths and serializer errors.

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_streaming_cold_state_root -- --ignored --nocapture
```

A release run on the same Intel Core i7-8550U measured **989.158 ms** for 32 full
Vec serialization/hash calls and **932.068 ms** for 32 streamed cold hashes over
100,000 UTXOs. The payload was 5,700,040 bytes; the stream buffer was 65,536 bytes.
Both paths bypass root memoization, alternate order, and check identical hashes.
These are single-run elapsed times, not an end-to-end sync speedup. The scratch
buffer figure excludes the existing ledger and small tree iterator stacks.

## Remaining costs

The first root for a new or changed state still serializes and hashes every live
entry, using the bounded hashing buffer. [Supply audits](SUPPLY_AUDIT_CACHE.md)
maintain guarded per-asset totals for changed data, while restore forces full audits.
The cache retains one key's shared roots until replacement or drop, potentially
keeping changed branches of one older state alive. It adds a short mutex and
reference-count operations to hits. Interleaved forks can evict a useful entry;
cache metadata is bounded to one entry per shared cache slot, with no root history.
Program storage remains whole-program copy-on-write on its first shared write.

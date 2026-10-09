# Structurally shared monetary state maps

`kernel::state_map::StateMap` replaces whole-table copy-on-write for coin UTXOs,
asset accounting records, asset shares, program records and derived owner and
deployment indexes. It is an ordered
AVL tree with `Arc` nodes. Cloning shares the root. Insert, removal and mutable
lookup copy shared nodes only along the affected search path and any rotation
paths. Exclusively owned nodes are reused. Lookup and mutation remain logarithmic
in entry count, with no accumulated overlay layers or global compaction step.

The owner indexes also use these maps at each level:

- Coin: owner -> map of share IDs.
- Asset: owner -> asset ID -> map of share IDs.

Copying a node therefore clones references to nested maps rather than an owner's
entire ID set. VM balance lookups still use the owner indexes. Input selection
order is unchanged.

## Canonical state and isolation

Serialization writes the historical `u32` entry count followed by sorted key/value
pairs. Tree shape, height, subtree lengths and sharing metadata are not encoded.
Deserialization uses the existing BTreeMap decoder, then constructs a balanced
tree from its sorted entries. Owner indexes are still reconstructed from primary
state and omitted from canonical encoding. Coin totals remain local to each state
copy and change alongside successful UTXO mutations.

All reads see the complete current state, including existing output IDs and values
in shared branches. Collision and ownership checks keep their original behavior.
Failed staged execution discards its private roots. Journal rollback restores
entries through the same mutation helpers, updating owner indexes and removing
empty groups. No consensus version, database schema, monetary rule or burn weight
changes. Existing compatible snapshots need no migration.

Asset `records()` and `shares()` now return immutable `StateMap` references rather
than BTreeMap references. Get, iteration, keys, values and indexing remain available.
Applications must still mutate monetary state through bound kernel hosts. Program
registry and owner/nonce deployment indexes also use shared trees. Program storage
still copies one program's complete map on its first shared write. Retained root
identities support [state-root memoization](STATE_ROOT_CACHE.md) without manual
dirty flags.

## Verification

Map tests compare generated insert/remove/mutable-lookup sequences and independent
forks against BTreeMap. They audit ordering, balance, height and subtree lengths,
check different insertion/deletion orders, byte-for-byte historical encoding,
restore and truncated data rejection. On 131,072 entries, clone counters assert
that first insert, update and removal each copy fewer than 128 values; the same
bound is tested inside a nested owner map. Coin and asset tests additionally check
original-state isolation, owner indexes, journals, supply and exact rollback.
Frozen vectors and workspace snapshot/replay/network/reorg tests cover integration.

## First-write measurement

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_utxo_first_write_paths -- --ignored --nocapture
```

The benchmark forks a populated UTXO set, consumes one input and creates one
output 128 times. All UTXOs belong to one owner, exercising the large owner-index
case. The previous whole-table implementation uses Arc/BTreeMap coin tables and
an Arc/BTreeMap/BTreeSet owner index; the optimized path uses actual UtxoSet
mutation methods. Both final canonical UTXO bytes and owner IDs must agree, and
the original state must retain its input. Timing includes clone, mutation and
replacement/drop of preceding fork results; initial fixture setup and final
encoding checks are outside the timed loops.

A release run on an Intel Core i7-8550U, after workspace tests completed:

| Entries, all owned by one program | Previous whole-table COW | Shared paths |
| --- | ---: | ---: |
| 20,000 UTXOs, 128 clone/spend rounds | 101.451 ms | 1.054 ms |
| 100,000 UTXOs, 128 clone/spend rounds | 648.571 ms | 1.605 ms |

These are elapsed-time microbenchmarks, not end-to-end node CPU or sync results.
Machine load and cache/allocator effects affect single-run numbers.

## Costs that remain

Each node has reference-count, allocation, child-link and balance metadata.
This can increase RAM per entry and reduce scan locality compared with BTreeMap.
Sorted iteration and full canonical serialization still visit every live entry;
cold state-root hashing and uncached supply audits remain linear. Repeated roots
and successful audits for unchanged data can use guarded caches.
See [supply audit caching](SUPPLY_AUDIT_CACHE.md). Snapshot restore builds trees
and owner indexes. Those workloads need separate profiling; first-write savings
do not establish an overall speedup for every workload.

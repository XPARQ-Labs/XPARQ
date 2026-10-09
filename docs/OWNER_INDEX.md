# Derived owner indexes

The ledger maintains two in-memory lookup structures:

- Coin: `Owner::Program(ProgramId) -> sorted CoinShare IDs`.
- Asset: `Owner::Program(ProgramId) -> AssetContract -> sorted Share IDs`.

The primary UTXO and asset-share maps remain authoritative. Indexed iterators
resolve each candidate through the primary map and check its owner, and asset
queries also check its asset ID. Consensus spending still checks the original
UTXO's owner and authenticated transaction signer or executing program.

## Updates and restoration

Coin insertion and consumption maintain index membership. Asset share insertion,
removal and replacement pass through private helpers, including mint, transfer,
burn and journal rollback. Empty asset/owner buckets are removed. No mutable
share-map accessor is exposed, so callers cannot bypass these helpers.

Indexes are skipped during canonical Borsh serialization. Deserialization rebuilds
them from primary entries; sparse quote views also rebuild from their captured
entries. Snapshot restore, replay and reorg therefore recover the same lookup
data without trusting serialized index contents. Clones share each index and its primary table roots. Both owner groups and their
nested share-ID maps use structurally shared trees; writes detach affected paths,
leaving other state copies unchanged without copying a large owner's full ID set.

Canonical ledger, snapshot and transaction bytes, state roots, burn weights,
chain-spec version and database schema are unchanged. Existing compatible
databases do not need migration for this index change.

## Consumers and ordering

Account UTXO/balance/activity responses use the coin-owner index. Asset balance
and share queries use the owner/asset index. Account asset-share responses still
sort the owner's entries by share ID to retain the previous response order.
The metadata listing still scans asset records to find creator/mint authorities,
but no longer scans all shares for each asset.

Legacy VM transfers retain ascending share-ID selection. XPVM v4 retains descending
amount then ascending share-ID selection. Its execution cache now loads only
programs whose balances are accessed. Effects update already-loaded caches;
programs accessed for the first time after a transfer read the current ledger,
including their existing funds and newly received outputs.

## Verification

Coin model tests compare indexed results with full scans across multiple owners
after generated insert/consume sequences. Asset model tests compare both index
levels with primary maps through registration, mint, transfer, burn and rollback,
including multiple owners/assets and deletion of the last share. Both assert the
historical map-only encoding and exact index reconstruction on decode. VM tests
cover transfers to programs accessed before or after receipt, and full rollback.
Frozen consensus vectors and existing network/snapshot tests provide additional
compatibility coverage.

Run the owner query microbenchmark:

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_owner_lookup -- --ignored --nocapture
```

An earlier BTreeMap/BTreeSet release run on an Intel Core i7-8550U, querying 100 owned UTXOs out of 100,000
total UTXOs 128 times, measured **190.786 ms** for scanning and **1.467 ms** for
indexed lookup. Both paths must return the same total. This is one elapsed-time
query microbenchmark, not an end-to-end sync or block-validation measurement.
It predates the structurally shared map representation; rerun the command to
measure the current indexed lookup.

A release run after the shared-tree change, with workspace tests already finished,
measured **748.794 ms** for scanning and **3.466 ms** for indexed lookup on the same
fixture sizes. The runs are not a controlled paired comparison, but the increased
pointer traversal and reduced scan locality need to be included when assessing
overall node performance. See the separate first-write benchmark in
[state maps](STATE_MAP.md).

## Costs and limits

The indexes consume additional RAM proportional to the number of live shares
and owner/asset groups. They contain IDs rather than copies of monetary entries,
and state clones share their tree roots. Mutations copy logarithmically sized
paths in shared trees and update exclusively owned nodes in place. Node allocation
and pointer traversal have costs compared with BTreeMap/BTreeSet; see
[state maps](STATE_MAP.md). Index restoration visits each primary entry and builds
ordered indexes. Cold state-root hashing, uncached supply audits and owner response
materialization remain
separate costs. This does not replace redb tables or add persistent balance caches.

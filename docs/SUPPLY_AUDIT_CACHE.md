# Incremental asset-supply validation

Normal `LedgerState::validate_supply_invariants()` checks coin accounting on every
call, then validates asset accounting. A successful full asset audit establishes
per-asset live-share totals. Checked kernel operations carry those totals forward
using their sparse journals and mark affected assets for validation. Normal checks
then compare only those assets' metadata, mint/burn counters and recorded supply
with the maintained totals. Unchanged asset data reuses its successful result.

## Safety and restore

The private summary retains the actual record and share StateMap roots, an ordered
map of totals, and an ordered set of pending assets. A summary can be read only
when its roots match the primary data. Root retention prevents address reuse and
forces later mutation to detach shared paths.

After a successful operation, the kernel subtracts all previous touched shares,
then adds their final values. Subtracting first avoids transient overflow during
transfers near the u128 limit. Register, mint, transfer and burn all use the same
journal path. Rollback applies the inverse changes. A failed operation restores
its original data and summary, including changes that failed after consuming
inputs. Multiple operations can accumulate pending assets before validation.
Checked arithmetic failure or a zero share discards the candidate summary and
requires a full audit. Failed validation never clears pending assets.

Raw record/share changes outside this path fail the root guards and fall back to
the full scan, even if a later valid operation runs. Missing or stale summaries
also require a full audit; there is no assumption that decoded data is valid.
Unchanged assets remain covered by the successful baseline and retained roots.
Changes to a fork detach its summary slot; unchanged clones can share it safely.
Concurrent or interleaved readers still check roots before using a shared slot.

The full audit retains its original checks and error ordering: zero shares,
unknown asset references, total overflow, invalid metadata, issuance beyond the
maximum, inconsistent mint/burn accounting and a live-share total different from
recorded supply. Coin accounting checks precede every normal asset check.

The kernel exposes explicit deep checks:

- `audit_asset_supply()` always scans all asset records and shares independently.
- `audit_supply_invariants()` additionally audits primary coin UTXOs.

Snapshot restore always uses the deep checks, including in-memory snapshots.
Borsh omits the entire summary; deserialize starts without one. Summary contents
are excluded from state equality. Canonical bytes, state roots, transaction
encoding, burn, database schema and chain-spec version stay unchanged. Applications
cannot supply totals, pending flags or summary roots.

## Verification

Tests compare maintained totals with independent share scans through multiple
pending assets, registration, mint, transfer, burn, reverse journals and failed
transfers after input consumption. They exercise the u128 boundary, fork isolation,
concurrency, stale summaries, raw data corruption, fresh deserialization and exact
historical encoding. Existing tests reject invalid metadata, unknown asset shares,
zero shares, overflow and inconsistent supply. A deliberately forged internal
memo still cannot bypass deep audits or snapshot restoration. Frozen vectors and
workspace replay, network, restart, snapshot and reorg tests cover integration.

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_incremental_changed_asset_supply -- --ignored --nocapture
```

A release run on an Intel Core i7-8550U built one asset with 100,000 shares and
performed 128 transfers, each changing one input and one output. Incremental
validation took **0.179 ms** in total, versus **2,046.604 ms** for full audits over
the same resulting states. Transfers and summary maintenance took **6.758 ms**,
measured separately; fixture construction and initial/final audits were outside
those timings. Each incremental check started with one pending asset and was
followed by an independent deep audit. The fixture had no coin UTXOs, so the deep
coin scan contributed negligible work. Timings measure elapsed time for these
paths, not end-to-end synchronization or an isolated comparison of mutation costs.

The older unchanged-data benchmark remains available:

```bash
cargo test -p kernel --release --lib --locked --offline \
  benchmark_unchanged_asset_supply_cache -- --ignored --nocapture
```

Before incremental updates were added, 128 unchanged checks over 100,000 shares
measured 2,389.376 ms for full scans versus 0.007 ms for cache hits. That historical
measurement covers unchanged data only.

## Remaining costs

The first audit, missing/stale summaries and explicit deep checks still scan the
full inventory. Restore still audits all coin UTXOs. Totals add one tree entry per
asset with live shares, and pending assets add at most one entry per touched asset
until successful validation. Updates copy affected tree paths; retained roots can
keep old branches alive while forks exist. Normal checks cost according to the
number of changed assets, while transfer execution and journal updates still cost
according to touched inputs/outputs. Cold state-root hashing remains a full scan.

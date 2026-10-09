# Repeatable CPU benchmarks

These use Cargo's optimized bench profile and standard-library timers. No new
benchmark dependency is required. Targets are explicitly selected because SHA2
comparison is optional and full block fixtures require the extension executor.

```sh
# Active account schemes: preparation, cold/prepared signing, valid/invalid verify
cargo bench -p crypto --bench signatures --locked --offline

# Complete block admission/application, with the runtime's SystemApplications
cargo bench -p extension --bench block_validation --locked --offline

# Opt-in: 168 distinct transactions, mixed schemes, near the 2 MiB limit
cargo bench -p extension --bench block_validation --locked --offline -- --signature-heavy --samples 3

# Real redb + valid chain: state roots, replay, core snapshot restore, Linux RSS
cargo bench -p node --bench ledger_sync --locked --offline -- --samples 3 --blocks 128 --state-utxos 50000

# Optional historical backend comparison; enables no SHA2 consensus account
cargo bench -p crypto --bench slh_compare --features slh-sha2-benchmark --locked --offline
```

The configurable targets accept `-- --quick` (one measured sample),
`-- --samples N` (default 5), and `-- --verify-rounds N` (default 100, relevant
to signatures only). A warmup is always excluded. Positive integer bounds are
checked. `--quick` is a functional smoke run, not a reliable performance result.
The historical SHA2 comparison retains five trials and 100 verify rounds.
`ledger_sync` defaults to 128 additional blocks and 50,000 target live UTXOs;
`--quick` uses eight additional blocks and 1,000 UTXOs. Construction/mining is
outside measurement and can take several minutes. `--signature-heavy` changes
the block fixture and is intended for `block_validation` only.

The measured pending-prefix optimization has a separate checked manual test:

```sh
cargo test -p node --bin node --release --locked --offline benchmark_pending_prefix_validation -- --ignored --nocapture --test-threads=1
```

Outputs contain comment lines beginning with `#` and CSV rows:
`case,operation,median_ms,min_ms,max_ms`. Verification statistics aggregate
per-sample averages, not individual latency percentiles. For even sample counts,
the median is the average of the two middle observations.

Run targets sequentially on an otherwise idle machine. Save output with the
revision, working-tree changes, `rustc -Vv`, CPU model, feature set and any
`RUSTFLAGS`. Keep those inputs fixed when comparing revisions. CPU scaling,
thermals, randomized ML-DSA signing and operating-system scheduling affect
results; small changes need repeated measurements.

For scope, fixture design, limitations and the initial measurements, see
[benchmark details](../docs/BENCHMARKS.md). Security compatibility checks remain
separate: [SLH internal review](../docs/SLH_AUDIT_2026-10-09.md).
See the [hardening report](../docs/HARDENING_2026-10-09.md) for follow-up
measurements, cache semantics and the independent-review handoff.

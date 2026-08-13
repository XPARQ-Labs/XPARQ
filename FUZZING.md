# XPARQ Fuzzing

The fuzz workspace tracks the current XPARQ core formats and consensus rules.
It covers canonical decoders and roundtrips, unified Transfer/QCash
blocks, atomic state transitions, QCash lifecycle and bearer files, address
encoding, WBDA epochs, authenticated artifacts, and block commitments.

## Targets

- `decode`, `decode_protocol`, `decode_block`: malformed canonical input;
- `roundtrip`: canonical block and protocol-transaction encode/decode;
- `state_transition`: Transfer and QCash success/failure atomicity,
  ledger invariants, and value conservation;
- `qcash_lifecycle`: withdrawal, full redeem, rejected signature atomicity,
  and exact rollback. Partial redeem and split conservation/rollback are also
  covered by deterministic core regression tests;
- `commitment_mutation`: transaction and block commitment mutation;
- `mixed_family`: all families in one ordered block plus hostile transaction
  count prefixes at and beyond consensus limits;
- `address_codec`: canonical lowercase `z1` Bech32 address roundtrips;
- `consensus_epoch`: exact 4,100-block WBDA windows, bounds, and epoch boundary;
- `artifact_codec`: generic `.XPARQ` and authenticated genesis decoding;
- `qcash_coin_codec`: strict `.QCash` decoding and canonical roundtrips.

The checked-in corpus selects every synthetic regression mode. Synthetic
fixtures are regenerated in-process, so corpus files remain small and do not
freeze private signing material or obsolete consensus encodings.

## Local bounded run

```bash
cargo install cargo-fuzz --locked
cd core
cargo +nightly fuzz run state_transition fuzz/corpus/state_transition -- \
  -max_total_time=60 -timeout=10 -rss_limit_mb=2048
```

Replace `state_transition` and its corpus path with another target. Use
`--no-default-features --features testnet` or `--features devnet` to select the
same compile-time network profile as the core. Every pull request compiles the
mainnet and devnet targets. Scheduled jobs use bounded time, input size, and
memory limits.

## Core benchmark

Run the network-independent core benchmark with:

```bash
cargo bench --bench core_consensus
```

Set `XPARQ_CORE_BENCH_ITERATIONS` to change the default sample count. Dedicated
SQIsign benchmarks remain available behind their corresponding feature flags.

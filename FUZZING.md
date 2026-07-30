# Paqus Fuzzing

The fuzz workspace covers canonical decoders, roundtrips, unified
mixed-family blocks, atomic state transitions, QCash withdraw/deposit and
rollback, and transaction/Merkle/witness commitment mutation.

## Targets

- `decode`, `decode_protocol`, `decode_block`: malformed canonical input;
- `roundtrip`: canonical block and protocol-transaction encode/decode;
- `state_transition`: Transfer, QCash, and Governance success/failure
  atomicity, invariants, and value conservation;
- `qcash_lifecycle`: withdrawal, matured deposit, fee conservation, rejected
  signature atomicity, and exact rollback;
- `commitment_mutation`: Merkle root, witness root, and witness-data mutation;
- `mixed_family`: all families in one ordered block plus hostile transaction
  count prefixes at and beyond consensus limits.

The checked-in corpus selects every synthetic regression mode. Synthetic
fixtures are regenerated in-process, so corpus files remain small and do not
freeze private signing material or obsolete consensus encodings.

## Local bounded run

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run state_transition fuzz/corpus/state_transition -- \
  -max_total_time=60 -timeout=10 -rss_limit_mb=2048
```

Replace `state_transition` and its corpus path with another target. Every pull
request compiles all targets. The scheduled workflow runs each security target
with a bounded time, timeout, input length, and RSS limit.


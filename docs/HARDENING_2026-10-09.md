# Crypto and node hardening — 2026-10-09

Implementation follows the requested sequence. The independent review remains
the final external step, not a claim made by this internal report.

## Secret buffers and wallet defaults

With `zeroize` enabled, unpublished WOTS/FORS PRF outputs, WOTS chain working
buffers and RNG construction buffers use guarded arrays. `SkSeed` and `SkPrf`
wipe their owned arrays independently, including unwinding paths. Public signing-key
Debug is redacted. Parameters, hash inputs and signature encoding are unchanged;
complete NIST signing known answers and pre-refactor fixtures pass. Rust moves,
registers and compiler copies still prevent guaranteed erasure of every historical copy.

New wallets default to **24 words for every scheme**, in CLI and interactive
mode. The user chose a default: explicit `--words 12` and existing recovery remain
supported. The CLI integration test checks all six saved-wallet defaults and
12-word identity recovery. Expanding a 12-word mnemonic cannot increase its
128-bit entropy; higher-strength schemes should use 24 words.

## Signature-heavy block

`--signature-heavy` funds and signs 168 distinct valid transactions, fourteen
inputs per key and two keys per active scheme. The measured block is
**2,001,157 bytes**, approximately **95.42%** of the 2 MiB limit.
Full in-memory validation/application including fresh PoW, authorization,
accounting and state root: **322.582 ms median**, range 321.564–323.409 ms,
three samples after an excluded warmup. This is a mixed-scheme workload;
application-specific worst cases need separate workloads.

```sh
cargo bench -p extension --bench block_validation --locked --offline -- --signature-heavy --samples 3
```

## CPU admission and mempool optimization

Preserved the kernel's authorization-before-state-access gate and cross-chain
rejection tests. Mismatched/inactive/malformed signature encodings return before
authorization-commitment construction. Existing bounded decoding, RPC/frame
limits, connection limits, duplicate IDs, fees and mempool size/count limits remain.

Added a local RAII gate limiting pending-operation admissions, including jobs
waiting on the mutation lock, to **two**. Busy callers receive a retry message;
drop/unwind releases permits. Hex length is checked before binary allocation;
operation structure and relay limits are checked before expensive validation.

A **256-entry FIFO rejection cache** avoids repeating the same failed candidate
under the same confirmed tip/state and ordered pending prefix. Its key contains
tip hash, state root, pending-prefix fingerprint and operation ID. A changed
anchor/prefix misses the cache. Validation failures are cached; persistence failures
are not. Unique modified candidates can still incur verification work. This is
not complete protection from distributed or sustained CPU denial of service.

The accepted-prefix cache retains fully validated state. New candidates still
traverse normal kernel authorization/execution. A missing cache or changed tip/state
replays the prefix completely. Append invalidates the copied prefix cache; the
new validated state is published only after persistence succeeds. Explicit
whole-pool validation continues to replay all transactions. These caches are
transient and do not affect received-block validation or canonical state.

An ML-DSA44 benchmark compares full replay with cached advancement; resulting
states must match. One excluded warmup, five measured samples, preparation and
storage/networking excluded:

| Existing pending transactions | Full replay ms | Cached advancement ms |
| --- | ---: | ---: |
| 0 | 0.244 | 0.254 |
| 16 | 3.579 | 0.211 |
| 64 | 14.277 | 0.223 |
| 128 | 31.036 | 0.217 |

At 128 transactions this is approximately 143× less validation time, not a
claim of 143× overall node throughput. Tests cover dependent children, validly
signed conflicting spends, forged children, state-root invalidation, bounded
rejections, permit unwinding and failed publication preserving accepted state.

## Replay and phase profiling

The benchmark uses the actual redb store in its own uniquely created temporary
directory. It mines funding, creates live UTXOs through valid transfers and extends
valid history. No user database is opened or removed. Replay verifies the tip/root
and independently audits supply. Snapshot restore exercises the core ledger
snapshot, not the node's outer checkpoint wrapper. This is local replay rather
than network synchronization.

The large fixture contains **143 post-genesis blocks**, **50,130 live UTXOs**
and **3,659,530 canonical state bytes**. Final three-sample median timings after fixing benchmark buffer lifetimes:

| Phase | ms |
| --- | ---: |
| state serialization | 5.079 |
| hash preencoded state | 24.244 |
| cold state root | 26.732 |
| snapshot serialization | 5.124 |
| read/decode history | 62.557 |
| header/PoW admission history | 16416.225 |
| execution/commit history | 4085.140 |
| full replay | 20570.871 |
| core snapshot restore | 16687.005 |

PoW represents about 80% of replay wall time, execution about 20%, and read/decode
about 0.3%. Phase timers are not hardware sampling. Frequency/load and small
sample counts affect results. No PoW check, protocol hash or consensus rule was
weakened for performance. Cold-root timing disables memoization on a cloned state;
both hashing paths must produce the committed root.

The initial harness HWM was 467,308 KiB, including retained PoW buffers and
multiple ledgers; it is **not a node RAM estimate**. The harness now releases
the unused setup buffer and completed replay/buffer before restoring the snapshot.
The final harness HWM is 300,504 KiB (about 293 MiB), including mining setup;
post-replay RSS is 61,892–63,636 KiB (about 60–62 MiB). These are harness
measurements, not predictions for a running node. RSS/HWM are printed on Linux;
high-water marks include setup and allocator retention. The earlier raw run is
retained separately; timing differences between runs are not an optimization claim.

```sh
cargo bench -p node --bench ledger_sync --locked --offline -- --samples 3 --blocks 128 --state-utxos 50000
cargo test -p node --bin node --release --locked --offline benchmark_pending_prefix_validation -- --ignored --nocapture --test-threads=1
```

Raw data: [benches/results](../benches/results). Intel i7-8550U, Rust 1.99.0,
x86_64 Linux, default compiler CPU target and mainnet features.

## Lint cleanup and independent review

Resolved the 19 initial kernel library warnings and six additional test warnings.
Kernel Clippy passes for all targets with `-D warnings`, without suppressing those
kernel warnings. Equivalent code changes preserve frozen encoding checks. The
public ledger module path is `kernel::ledger::canonical`; the former
`kernel::ledger::ledger` alias has been removed.

The [independent-review handoff](INDEPENDENT_SECURITY_REVIEW.md) is prepared for
a separate reviewer. No independent audit, NIST module validation or formal
side-channel proof has been completed by the implementing agent.

## Verification

Release workspace tests passed: 313 passed, 20 ignored, zero failures.
After strengthening the conflicting-spend test, the node suite was rerun:
64 passed, three ignored, zero failures. Optional SHA2 crypto tests, default
workspace all-target checks, devnet all-target checks and kernel all-target
Clippy with warnings denied also passed. Ignored benchmarks were run explicitly
where reported above. No live chain or wallet was reset.

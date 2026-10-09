# Signature and block-validation benchmarks

Commands and configurable sample counts: [benches README](../benches/README.md).
Harnesses use standard-library timing, one excluded warmup, checked outcomes,
and median/minimum/maximum measurements. No consensus rule is modified.

## Signature measurements

[`crypto/benches/signatures.rs`](../crypto/benches/signatures.rs) exercises all
six active schemes with a 32-byte message and public synthetic seeds:

- `prepare_public_key`: a new SigningSeed's lazy key preparation and public-key
  extraction. Creating the seed wrapper is outside this measurement.
- `sign_cold_with_keygen_and_drop`: seed wrapper allocation, lazy key preparation,
  signing, signature allocation and key drop/zeroization.
- `sign_prepared`: signing and signature allocation using an already prepared
  key. Key preparation and drop are outside the timed region.
- Verification through the same `crypto::verify` entry point used by account
  authorization, including backend parsing. Cases are valid signatures and
  well-formed signatures with the first or last byte modified. Rejection is
  asserted on every iteration. Malformed length/tag rejection is not measured.

This isolates account crypto; it excludes canonical transaction decoding,
ProgramId derivation, ledger work, disk and networking. ML-DSA signatures are
randomized, so cold and prepared signatures are verified instead of compared
for equality. Each sample uses a new synthetic seed and message.

Initial measured run: 9 October 2026, Intel i7-8550U (4 cores, 8 logical CPUs),
x86_64 Linux, Rust 1.99.0 / LLVM 23.1.1, default CPU target, Cargo bench profile
with debug symbols, default mainnet features. Three measured samples per scheme,
100 verifies per case/sample, one excluded warmup. Times are median milliseconds:

| Scheme | Cold signing | Prepared signing | Valid verify |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 0.710 | 0.415 | 0.178 |
| ML-DSA-65 | 1.038 | 0.584 | 0.268 |
| ML-DSA-87 | 1.275 | 0.556 | 0.424 |
| SLH SHAKE128s | 1744.163 | 1520.824 | 1.496 |
| SLH SHAKE192s | 2805.011 | 2600.386 | 2.176 |
| SLH SHAKE256s | 2428.731 | 2233.777 | 3.148 |

Signing speed need not increase monotonically with security level: these
parameter sets trade different tree layouts. Results describe this backend and
machine, not a universal ranking. See [SHA2/SHAKE comparison](SLH_BENCHMARK.md)
for backend comparison; SHA2 remains excluded from account authorization.

## Complete block validation

[`extension/benches/block_validation.rs`](../extension/benches/block_validation.rs)
installs `SystemApplications`, as the runtime does. A bare non-test kernel
intentionally has no application executor and fails closed for transfers.
This location avoids a kernel-to-extension dependency.

The fixture starts from genesis, mines an emission, and performs a valid funding
transfer to two independent keys per scheme. There is no injected ledger balance.
Measured blocks contain twelve independent authorized native-coin transfers:

- `mixed_small`: one output per transaction.
- `mixed_near_limit_many_outputs`: 3800 outputs per transaction; canonical block
  bytes must be between 90% and 100% of the protocol's 2 MiB limit. Individual
  transactions remain within their item/byte limits. The actual size and weight
  are printed so that a future encoding change causes a visible failure.

`apply_block_including_pow` times the actual `apply_block_with_pow_memory` path:
structure/header checks, fresh PoW verification with a reused buffer, signature
authorization, ownership/value/burn checks, execution, accounting, state root,
and in-memory block commit. Setup signing, mining, initial state cloning, buffer
allocation, and subsequent supply audits are excluded. The normal ledger's
internal staging and bookkeeping remain inside the measured call.

Every sample begins from the same funded baseline; replaying against an already
spent ledger is avoided. A warmup uses the same path. After every application,
the committed root must match the block and coin supply is independently audited.

This is an output-heavy near-limit fixture with twelve signatures, not a
worst-case signature-heavy block. It does not measure storage writes, network
admission, long-history synchronization, VM workloads, asset workloads or parallel
validation. Block validation takes an already constructed typed block, so wire
decoding is outside the timer.

Initial run on the machine described above: five measured samples per case,
one excluded warmup. Same benchmark executable, features and fixture baseline:

| Case | Canonical bytes | Limit utilization | Median ms | Min ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| mixed_small | 143093 | 6.82% | 98.753 | 98.135 | 99.928 |
| mixed_near_limit_many_outputs | 2012201 | 95.95% | 269.771 | 267.446 | 274.017 |

The crypto and block measurements were run sequentially. CSV results are
retained under [`benches/results`](../benches/results).

## Validation of the harnesses

Both main benchmark targets completed all assertions. The optional SHA2 target
was compiled with its feature enabled; its algorithm/comparison code is moved
from the existing example, whose historical measurements are retained.
Focused Clippy (`-p crypto -p extension --benches --no-deps`, with the SHA2
feature, `-D warnings`), focused rustfmt checks and `git diff --check` passed.
Subsequent [hardening](HARDENING_2026-10-09.md) resolved the original 19 kernel
library warnings and six test warnings; kernel Clippy now passes for all targets.
That report adds signature-heavy blocks, large-state replay phase measurements,
memory interpretation and measured pending-prefix caching. Original tables above
remain records of the earlier run.

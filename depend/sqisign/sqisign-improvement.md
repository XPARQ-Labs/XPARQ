# XPARQ SQIsign improvement plan and changelog

## Status

SQIsign is a NIST Round 3 candidate. The `xparq-sqisign` 0.1.0 crate is based
on the vendored `sqisign-rs` 0.5.0
implementation is not the official NIST reference implementation and states
that it has not been independently audited. XPARQ activates this implementation
only in the isolated devnet profile. Mainnet and testnet remain on ML-DSA-44;
this hardening work does not migrate either network or change their wire format.

Baseline:

- `xparq-sqisign`: 0.1.0 (vendored `sqisign-rs` 0.5.0 baseline)
- `sqisign-verify`: 0.5.0
- security level prepared by XPARQ: Level 5
- XPARQ mainnet/testnet registry status: `CandidateInactive`
- XPARQ devnet status: active through `sqisign-blockchain-test`
- baseline source provenance commit: `6748f52413798d0112266a24987bba7b87953b37`

## Non-negotiable acceptance gates

Every implementation change must pass. The reproducible local entry point is
`sh depend/sqisign/tools/run-validation-gates.sh`.

1. Default XPARQ build without the candidate feature.
2. Offline build with `sqisign-candidate`.
3. SQIsign Level 1, 3, and 5 known-answer tests.
4. Rust/reference cross-verification in both directions.
5. Canonical-encoding and malformed-input regression tests.
6. Level 5 dual-authorization negative tests.
7. Before/after benchmark comparison.
8. No change to XPARQ mainnet/testnet consensus or wire encoding while the
   candidate is inactive on those networks.

A dependency major-version upgrade must be isolated by compatibility group.
The interdependent `signature`, `rand_core`, and `rand` migrations form one
group. SHA3/SHAKE,
fixed-width arithmetic, and variable-width arithmetic must never be upgraded
in the same change.

## Dependency roadmap

| Group | Current | Target | Risk | Status |
|---|---:|---:|---|---|
| `signature` | 2.2.0 | 3.0.0 | API/trait compatibility | migrated; validation partial |
| `rand_core` | 0.6.4 | 0.10.1 | RNG trait compatibility | migrated; validation partial |
| `rand` | 0.8.7 | 0.10.2 | RNG behavior/API | migrated; validation partial |
| `crypto-bigint` | 0.6.1 | 0.7.5 | verifier arithmetic | migrated; validation partial |
| `num-bigint` | 0.4.8 | 0.5.1 | signing arithmetic | migrated; validation partial |
| `sha3` | 0.10.9 | 0.12.x or local SHAKE | transcript compatibility | last |
| `hybrid-array` | 0.4.13 | 0.4.13 | none | current |
| `subtle` | 2.6.1 | 2.6.1 | none | current |
| `zeroize` | 1.9.0 | 1.9.0 | none | current |

## Hardening roadmap

- [x] Replace serialized candidate secret `Vec<u8>` storage with a fixed-size,
  zeroized allocation.
- [x] Prevent secret cloning and redact all formatting.
- [x] Contain panics reachable through the XPARQ candidate keygen/sign adapter
  and return `CandidateError::InternalPanic`.
- [x] Make raw secret-display helpers unavailable by default; accessing the
  helper now requires the explicit `dangerous-secret-display` vendor feature.
- [x] Make candidate key/signature fields private and require canonical vendor
  parsing through typed `from_bytes` constructors.
- [x] Make candidate verification fail closed when a vendor invariant panics.
- [x] The retired nested-core parser fuzz target covered public keys,
  signatures, and signing keys at Levels 1, 3, and 5. A replacement harness
  must be introduced deliberately before SQIsign activation work resumes.
- Add differential fuzzing against the official reference implementation.
- [x] Add deterministic worst-case verification work accounting before any
  mainnet/testnet consensus activation.
- [x] Add an opt-in paired signing-timing diagnostic. Production-target
  measurements and independent side-channel review remain required.

## Current XPARQ validation automation

- The legacy nested-core fuzz fixtures were retired during the root-crate
  migration; no current fuzz harness is claimed by the validation script.
- Pinned KAT checksums are verified before KAT execution.
- The official C/Rust bidirectional runner now resolves the XPARQ workspace
  correctly and runs when `SQISIGN_C_SOURCE` points at the pinned checkout.
- `verify_batch_parallel_accounted` reports signature checks, worst-case key
  decodes, and message bytes independently of the process-local verifier cache.
- `XPARQ_SQISIGN_TIMING_SAMPLES=N` enables the benchmark timing diagnostic;
  its output is diagnostic data, not a constant-time certification.

Still deliberately excluded:

- mainnet/testnet activation or transaction/account wire migration;
- automatic download of the official C implementation;
- claims of production side-channel resistance without multi-platform testing
  and independent review.

## RNG/signature migration validation

Completed:

- XPARQ default workspace and isolated SQIsign dependency builds.
- Level 1, 3, and 5 seeded keygen/sign/verify round trips.
- Modified-message and wrong-key rejection.
- `signature` 3 randomized signing and signature encoding.
- Injected entropy failure propagation through `RandomizedSigner`.
- XPARQ candidate integration-test and benchmark compilation.

Available:

- Official SQIsign-team Round-2 KAT files for Level 1/3/5 are pinned from
  `SQISign/the-sqisign` commit
  `dd133d7aca576c361a270c8e6434832535b42ecc`. Their SHA-256 checksums and
  provenance are recorded in `reference/KAT/PROVENANCE.md`.
- All 100 verifier vectors at each of Level 1, 3, and 5 pass for standard,
  expanded, and compressed formats under the explicit `kat-compat` feature.

Still open:

- The older internal signing-precomputation comparison test cannot run because
  `tools/c-validate/signing_precomp_expected.txt` is absent. End-to-end
  signature interoperability with the official C verifier is covered
  separately and passes.
- HD oracle suites cannot run because
  `sqisignhd-harness/test_vectors_l1.json` is absent.
- Old/new byte-for-byte differential signing still requires an isolated build
  of the 0.8/0.6/2 dependency baseline.

The `signature` 3 fallible-RNG trait is adapted by reading a 32-byte seed and
using `StdRng` internally. This propagates entropy failure before signing, but
means trait-based randomized signatures are not expected to consume the same
external RNG stream as the old `signature` 2 adapter. The direct SQIsign
`sign` API still consumes the supplied RNG directly.

## Local dependency mapping

Compatible dependencies now use explicit shared XPARQ paths, including when
`xparq-sqisign` is built as a standalone crate:

- `hybrid-array` 0.4.13, `subtle` 2.6.1, and `zeroize` 1.9.0
- `num-traits` 0.2.19
- `rand_core` 0.10.1 and `signature` 3.0.0
- `shake` 0.1.0, `digest` 0.11.3, `crypto-common` 0.2.2, `keccak` 0.2.0,
  and `sponge-cursor` 0.1.0 for production SQIsign transcripts
- `digest` 0.10.7, `crypto-common` 0.1.7, `block-buffer` 0.10.4,
  and `generic-array` 0.14.7 are retained only for legacy compatibility and
  the transcript differential oracle
- `getrandom` 0.4.3, `cfg-if` 1.0.4, and `libc` 0.2.189
- `cpubits` 0.1.1, `ctutils` 0.4.2, and `cpufeatures` 0.3.0
- `proc-macro2`, `quote`, `syn` 2, `unicode-ident`, `autocfg`, and
  `version_check`

Twenty-one redundant copies under `dependencies/sqisign` were removed after
the root and standalone builds resolved to the shared paths.

Dependencies intentionally retained separately:

- `sha3` 0.10.9 and `keccak` 0.1.6: retained only in the development graph as
  a byte-for-byte oracle. They are no longer in the SQIsign production graph.
- `crypto-bigint` 0.7.5, `num-bigint` 0.5.1, and `num-integer` 0.1.46:
  XPARQ has no other matching local implementation.
- `rand` 0.10.2 and `chacha20` 0.10.1: there was no pre-existing equivalent
  local crate; these copies are now shared through explicit paths.
- `paste` 1.0.15 and `libm` 0.2.16: XPARQ has no duplicate matching copy.
- Test-only `criterion`, `serde_json`, `hex`, and `hex-literal`: there are no
  matching local copies and they are not part of the production graph.

## Changelog

### 2026-08-09 — XPARQ validation and fuzz hardening

- Kept SQIsign isolated to devnet and made no mainnet/testnet consensus or wire
  changes.
- Repaired all stale core fuzz fixtures for the owned-XPQ UTXO and current
  QCash transaction APIs.
- Added a feature-gated parser fuzz target for SQIsign public keys, signatures,
  and signing keys across Levels 1, 3, and 5.
- Added deterministic, cache-independent worst-case accounting to SQIsign batch
  verification and exposed the accounting in the verifier benchmark.
- Added an opt-in paired signing-timing diagnostic with an explicit warning
  that it is not a side-channel certification.
- Added pinned KAT checksum verification and a single local validation-gate
  runner.
- Corrected the official C/Rust runner's workspace resolution for the XPARQ
  layout.
- Updated scheduled fuzz CI paths and added weekly SQIsign validation and parser
  fuzz jobs.

### 2026-07-29

- Built the official C reference implementation at pinned commit
  `dd133d7aca576c361a270c8e6434832535b42ecc` with its reference backend and
  bundled mini-GMP.
- Completed bidirectional C/Rust signature interoperability: all official
  Level 1/3/5 KAT signatures verify in Rust, and fresh Rust Level 1/3/5
  signatures verify in the official C implementation.
- Confirmed the official C verifier rejects a bit-flipped Rust signature at
  every security level, and added a reproducible test-only bridge and runner.
- Added the official SQIsign-team Round-2 `.req`/`.rsp` KAT corpus for Levels
  1/3/5, pinned its upstream commit and SHA-256 checksums, and corrected the
  vendored harness paths.
- Passed all 28 KAT harness tests, covering all 100 vectors for each of Levels
  1, 3, and 5 across standard, expanded, and compressed signature formats.
  These are NIST-format candidate vectors, not final FIPS validation vectors.
- Added signing and verification transcript boundary modules and moved the
  SQIsign production graph from `sha3` 0.10.9/`keccak` 0.1.6 to XPARQ-local
  `shake` 0.1.0/`keccak` 0.2.0 using `digest` 0.11.3.
- Added differential SHAKE256 tests covering empty input, multipart absorb,
  chunked squeeze, and lengths around the 136-byte SHAKE256 rate. The local
  backend is byte-identical to the legacy backend for every tested case.
- Moved `sha3` 0.10.9 to a test-only `sha3_legacy` oracle and removed the old
  SHA3/Keccak patches from the XPARQ production manifest.
- Ported the feature-gated SQIsign-RK SHAKE RNG to `rand_core` 0.10
  `TryRng`/`TryCryptoRng`; the feature builds again.
- Passed all 30 verifier library tests and Level 1/3/5 sign/verify plus
  malformed-input regression tests with the local transcript backend.
- Updated test/benchmark dependencies: `criterion` 0.5/0.7 to 0.8.2 and
  `hex-literal` 0.2/0.4 to 1.1.0.
- Restored the missing optional `blobby` 0.3 dependency in the local
  `digest` 0.10 compatibility crate so the SHA3 development vectors compile.
- Ported the SQIsign benchmark from removed `rand::thread_rng()` to
  `rand::rng()`.
- Confirmed the XPARQ candidate build, Criterion signing benchmark, SHA3,
  SHAKE and cSHAKE vectors, and Level 1/3/5 sign/verify round trips. The two
  long-running TurboSHAKE vectors were stopped after exceeding 60 seconds.
- The legacy SHA3 backend remains a development oracle in addition to the
  imported Round-2 KAT corpus; C cross-validation and SQIsignHD oracle assets
  are still absent.
- Redirected compatible SQIsign dependencies to explicit shared XPARQ paths
  and removed 21 redundant vendored copies.
- Added this improvement plan before dependency modernization.
- Recorded the vendored source baseline and dependency versions.
- Defined mandatory gates for every future dependency upgrade.
- Marked major dependency upgrades as blocked until the KAT/reference gate is
  reproducible locally.
- Completed fixed-size key/signature wrapper hardening and removed secret-key
  cloning; this does not change SQIsign
  cryptographic output or consensus behavior.
- Disabled raw secret-key formatting in normal builds.
- Added panic containment around candidate Level 5 key generation and signing.
- Added validated key/signature constructors and fail-closed panic containment
  to verification.
- Migrated SQIsign direct dependencies to local `rand` 0.10.2,
  `rand_core` 0.10.1, and `signature` 3.0.0.
- Ported deprecated `RngCore`, `thread_rng`, and randomized-signing APIs.
- Added Level 1/3/5 migration round trips and entropy-failure regression
  coverage.
- Recorded missing KAT/reference assets and the remaining `num-bigint` 0.4
  transitive `rand` 0.8 dependency.
- Migrated `num-bigint` 0.4.8 to local 0.5.1 with its `rand_0_10` feature,
  removing transitive `rand` 0.8 and `rand_core` 0.6 from the candidate graph.
- Passed 130 internal arithmetic tests, 16 serialization/malformed-input
  tests, 8 signing/trait tests, and Level 1/3/5 keygen-sign-verify round trips
  after the `num-bigint` migration.
- Migrated `crypto-bigint` 0.6.1 to local 0.7.5 and ported runtime Montgomery
  arithmetic to `FixedMontyForm`/`FixedMontyParams`.
- Passed 130 signing-arithmetic tests, 29 verifier/parser tests, serialization
  regressions, and Level 1/3/5 round trips after the `crypto-bigint` migration.
- Added a self-contained malformed Level 1 corpus covering truncated,
  all-zero, and multi-position mutated signatures with panic detection.
## 2026-07-29 — XPARQ verifier hot-path

- `CachedVerifyingKey` now owns an `Arc` to a decoded SQIsign Level 5 public
  key instead of decoding the same 129-byte key on every call.
- Added a process-wide, bounded 4,096-entry public-key cache. Invalid
  signatures are never cached as valid results.
- Replaced per-transaction scoped thread creation with persistent verifier
  workers.
- Added ordered `verify_batch_parallel` for independent crypto
  preverification.
- Added `sqisign_verifier` benchmarks for public-key decode, cold/warm single
  verification, dual verification, and simulated block batches.

Release-profile sanity result on the development host, one measured iteration:

| Operation | Time |
| --- | ---: |
| Decode public key | 246 µs |
| Single verify, cold cache | 42.14 ms |
| Single verify, warm cache | 41.92 ms |
| Dual verify, persistent pool | 78.00 ms |
| Batch of 16 dual-signature transactions | 560.36 ms |

The 16-transaction batch is roughly 55% faster than repeating the measured
dual-verification latency serially. Public-key decoding is only a small part of
single-verification time; the main cost remains SQIsign Level 5 arithmetic.

Block state transitions are intentionally not executed in parallel.
Transactions using stored authorization keys depend on account state produced
by earlier transactions in consensus order. A future two-phase block validator
may resolve keys/state sequentially, preverify the resulting independent crypto
jobs in parallel, then commit state sequentially.

## 2026-07-29 — Core secret-memory hardening

- SQIsign blockchain builds now install the crate's zeroizing global allocator
  from XPARQ core. Heap blocks used by bigint/arithmetic intermediates are
  scrubbed before deallocation or relocation.
- Signing-key serialization now returns `Zeroizing<Vec<u8>>`; both the internal
  fixed-size secret encoding and combined secret/public encoding are scrubbed
  on every return path.
- Deterministic key derivation now uses zeroize-enabled `ChaCha12Rng` directly
  instead of `rand::StdRng`. It preserves the exact previous byte stream while
  zeroizing the key, generator state, and buffered output on drop.
- Added a compatibility test comparing 256 bytes of the old and hardened RNG
  streams and a compile-time `ZeroizeOnDrop` assertion.

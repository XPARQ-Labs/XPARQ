# SLH-DSA SHA2-256s versus SHAKE-256s

Measured 9 October 2026 on Intel Core i7-8550U, x86_64 Linux, Rust 1.99.0,
RustCrypto slh-dsa 0.2.0-rc.5. Release profile, default compiler CPU target.
This benchmark adds no account scheme or consensus activation for SHA2.

Both variants use Pure SLH-DSA, empty context, deterministic signing and a
32-byte message. Both produce 64-byte public keys and 29,792-byte signatures.
One warmup is excluded, followed by five measured trials per backend with
alternating backend order. Both receive the same FIPS keygen input seeds and
messages for each trial. Signing uses an already prepared key. Every verification
includes parsing the encoded public key and signature; each case runs 100 times
per trial. Every valid result is asserted, and modified signatures must fail.

The first table records the backend before SHAKE dependency sharing.
Times below are milliseconds, median [minimum..maximum]. Verification statistics
are medians of the five per-trial average times, rather than individual-call
latency percentiles.

| Operation | SHA2-256s | SHAKE-256s |
| --- | ---: | ---: |
| keygen | 133.265 [130.934..170.696] | 439.474 [438.239..445.989] |
| sign_prepared_key | 1622.263 [1590.019..1697.407] | 5249.530 [5203.995..5349.537] |
| verify_valid | 2.208 [2.121..2.395] | 7.195 [6.900..8.570] |
| verify_invalid_first_byte | 2.204 [2.148..2.297] | 7.212 [6.988..7.941] |
| verify_invalid_last_byte | 2.312 [2.141..2.719] | 7.089 [6.936..8.288] |

On this machine SHA2-256s signing was about 3.24 times faster, and valid
verification about 3.26 times faster. Both modified-signature cases cost about
as much as valid verification, so rejecting a well-formed invalid signature
should not be treated as cheap admission work.

These are backend timings, not full wallet, block-validation or synchronization
throughput. Seed expansion, canonical transaction decoding, UTXO checks, state
roots, storage and networking are excluded. Small sample count, CPU frequency,
implementation and machine load limit generalization to other hardware. This
comparison is specific to 256s; it does not rank all SLH parameter sets.

Reproduce:

```sh
cargo bench -p crypto --bench slh_compare --features slh-sha2-benchmark --locked --offline
```

Source: [slh_compare.rs](../crypto/benches/slh_compare.rs). The previous example
command remains compatible and includes this same source. See the
[benchmark guide](BENCHMARKS.md) for all active schemes and full block validation.
SHA2-256s is a candidate for further testing; enabling it would require explicit
scheme IDs, account/wallet integration, vectors and a consensus identity update.

## After shared SHAKE/Keccak refactor

Same machine, compiler, release profile and benchmark procedure. Public-key and
signature compatibility fixtures and official NIST vectors pass. Results remain
machine-specific; timings from separate runs also reflect frequency/load changes.

| Operation | SHA2-256s | Shared SHAKE-256s |
| --- | ---: | ---: |
| keygen | 111.602 [108.998..114.834] | 197.941 [189.358..200.878] |
| sign_prepared_key | 1407.974 [1356.249..1471.657] | 2410.086 [2269.601..2574.916] |
| verify_valid | 1.929 [1.852..2.063] | 3.272 [3.103..3.420] |
| verify_invalid_first_byte | 1.958 [1.868..2.236] | 3.267 [3.216..3.575] |
| verify_invalid_last_byte | 1.955 [1.869..2.068] | 3.246 [3.047..3.379] |

The shared backend uses `shake 0.1.0` and vendored `keccak 0.2.0`; the
earlier table used SLH’s `sha3 0.11` with a separate Keccak dependency.
In this run SHA2 signing was about 1.71 times faster than shared SHAKE, compared
with 3.24 times in the earlier run. Default crypto builds exclude SHA2/HMAC.

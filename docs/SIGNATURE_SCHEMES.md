# Account signature schemes

The root signature authorization policy accepts these schemes in chain-spec 9:

| Protocol ID | Wallet name | Public key bytes | Signature bytes |
| --- | --- | ---: | ---: |
| 1 | mldsa44 | 1312 | 2420 |
| 2 | mldsa65 | 1952 | 3309 |
| 3 | mldsa87 | 2592 | 4627 |
| 5 | slhdsa-shake128s | 32 | 7856 |
| 6 | slhdsa-shake192s | 48 | 16224 |
| 7 | slhdsa-shake256s | 64 | 29792 |

ID 4 remains reserved for the existing SQIsign candidate and is rejected by the
account proof decoder. SHA2, fast (`f`) SLH variants and HashSLH-DSA prehash modes
are not registered for account authorization. The backend library also contains
these implementations; their presence does not enable them in consensus.

`signature.rs` owns the shared scheme, bounded proof encoding and dispatch;
`mldsa.rs` and `slhdsa.rs` implement the two families. Root account support is
explicitly committed to the chain-spec, separate from candidate upgrade plans.
The default remains ML-DSA44. Custom VM program IDs use the existing derivation.

Program identity remains
`H(policy || scheme || canonical_public_key || salt32)`, using the existing
SHA3-256 domain and length framing. ML-DSA IDs and wallet derivation are unchanged.
An SLH proof must match its scheme, exact lengths, public key, salt, signer
ProgramId and transaction commitment. Changing the owner or scheme cannot give
access to another program's UTXO. Signing still uses the normal root policy;
this does not add a VM opcode to verify arbitrary signature algorithms.

SLH authorization uses FIPS 205 **Pure** signing with empty context. The message
is the kernel's chain-bound, domain-separated authorization commitment. Signing
that commitment does not select the FIPS HashSLH-DSA prehash interface.
Deterministic signing uses `opt_rand = PK.seed` as permitted by FIPS 205.

The wallet stores a 32-byte master seed, not the expanded FIPS secret key.
SLH keygen input is the first `3*n` bytes of
`SHAKE256("XPARQ_SLH_DSA_KEYGEN_V1" || scheme_id_u8 || seed32)`, split into
`SK.seed`, `SK.prf`, `PK.seed` (n = 16/24/32). Expanded secret key lengths are
64/96/128 bytes. `SigningSeed` lazily prepares a typed signing key once per
wallet session and reuses it for public-key lookup and signing. There is no
global key cache or serialization of the prepared key. Seed buffers and typed
signing keys are zeroized when the wallet is dropped. Seed
expansion cannot increase the entropy of a mnemonic; use 24 words for the higher
security levels. New wallets default to 24 words for every scheme in CLI and interactive mode.
Existing wallet file version 2 remains readable; selecting a different signature
scheme derives a different identity and does not migrate funds.

Example:

```sh
./target/release/wallet new --wallet slh-wallet.json --account slhdsa-shake128s --words 24
```

Fees and archival burn continue to use actual canonical transaction bytes, so
larger SLH signatures increase transaction cost. No separate algorithm surcharge
is introduced. Signing the small variants takes more CPU than ML-DSA; debug builds
optimize the crypto/hash packages to keep wallet operations practical. Fee
convergence can still produce multiple signatures; it reuses the prepared key.
The cache changes no ProgramId, signature bytes, wallet format or consensus rules.

This consensus change uses chain-spec **9**, database schema **17**, and requires
fresh compatible chain storage. Wallet file version 2 and snapshot format 3 are
unchanged. No database reset is performed by this change.

The vendored backend is RustCrypto `slh-dsa = 0.2.0-rc.5`, upstream commit
`58bae19939c244ec4ef83bf16235b41b5b9c3c83`, with the `zeroize` feature. This is a
release candidate; its upstream README states it has not been independently
audited. The local fork routes SLH SHAKE operations through the same `shake` and
`keccak` packages used by ML-DSA and protocol SHA3. SHA2/HMAC are optional,
enabled by `crypto/slh-sha2-benchmark`; no SHA2 account is registered. See the
[local patch record](../depend/slhdsa/slh-dsa/XPARQ_PATCHES.md). The implementation is not claimed to have NIST validation.

Tests include official NIST ACVP FIPS205 keygen and external Pure verification
vectors for all three selected sets, independent Python SHAKE256 seed-expansion
and ProgramId fixtures, altered messages/signatures and kernel foreign-owner
spend rejection. Verification vector provenance is recorded in
[`crypto/tests/vectors/slhdsa/README.md`](../crypto/tests/vectors/slhdsa/README.md).

References: [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final),
[RustCrypto SLH-DSA](https://github.com/RustCrypto/signatures/tree/58bae19939c244ec4ef83bf16235b41b5b9c3c83/slh-dsa).

The release-mode [SHA2-256s/SHAKE-256s backend comparison](SLH_BENCHMARK.md)
includes reproducible timings for keygen, signing and valid/invalid verification.
SHA2 remains a benchmark-only candidate.

See the [shared SHAKE internal review](SLH_AUDIT_2026-10-09.md) for complete NIST
signing-vector checks and the initial findings. Guarded seed and WOTS/FORS/chain
buffers strengthen wiping; Rust compiler copies still prevent complete historical
secret-erasure guarantees. See the [follow-up hardening](HARDENING_2026-10-09.md).

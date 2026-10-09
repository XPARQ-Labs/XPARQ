# XPARQ local SLH-DSA patches

Base: RustCrypto slh-dsa 0.2.0-rc.5, commit
58bae19939c244ec4ef83bf16235b41b5b9c3c83. Original licenses and Cargo.toml.orig
are retained. This local fork is not claimed to have independent audit or NIST
module validation.

Changes:

- `hashes/shake.rs` uses the existing `shake 0.1.0` implementation instead of
  `sha3 0.11`. It retains the same SHAKE256 inputs, address serialization,
  output lengths and FIPS 205 parameter sets. The hypertree test helper also
  uses the shared SHAKE implementation.
- `shake` shares XPARQ's vendored `keccak 0.2.0`, `digest 0.11.3` and
  sponge-cursor. `zeroize` also enables `shake/zeroize`.
- SHA2/HMAC are optional under feature `sha2`. Their exports, parameter-size
  implementations, compressed SHA2 addresses and test expansions are gated.
  The SHAKE implementation is always available.
- Local manifests resolve dependencies to vendor paths. Original upstream
  manifest is provenance, not the active XPARQ feature configuration.

The crypto crate exposes `slh-sha2-benchmark` to opt into comparison only.
Default account authorization still accepts only Pure SHAKE 128s/192s/256s.
SHAKE fast parameters remain library types and are not account schemes.

Compatibility checks include official NIST FIPS205 keygen and Pure verification
cases and fixed public-key/signature-digest fixtures captured from the previous
backend for all three active SLH schemes. The fixture seed is [31; 32], message
is `dependency-sharing-regression`, signature digest is the unchanged protocol
SHA3-256 hash. Generator: crypto/examples/slh_compat.rs.

No wallet format, ProgramId derivation, consensus rule or chain-spec version
changes are needed for these byte-compatible implementation changes.

Follow-up hardening guards WOTS/FORS PRF and WOTS chain buffers, independently
wipes `SkSeed`/`SkPrf`, guards RNG construction buffers and redacts signing-key
Debug. Mathematical parameters and signature bytes remain unchanged. NIST
signing/compatibility tests are repeated. See the
[follow-up report](../../../docs/HARDENING_2026-10-09.md).

The [2026-10-09 internal review](../../../docs/SLH_AUDIT_2026-10-09.md)
adds complete NIST deterministic signing known answers and independent SHAKE
rate-boundary tests. It records remaining wallet entropy and secret-intermediate
wiping limitations; this is not an independent audit.

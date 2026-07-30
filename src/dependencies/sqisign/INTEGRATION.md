# SQIsign integration staging

This directory contains the vendored SQIsign dependency graph, maintained by
Paqus as the `paqus-sqisign` 0.1.0 candidate crate.
SQIsign is a NIST Round 3 candidate, not an approved Paqus consensus signature
scheme and not yet a final NIST standard.

## Current state

- The active Paqus signature scheme remains ML-DSA-44 (FIPS 204).
- SQIsign is available only through the disabled-by-default
  `sqisign-candidate` Cargo feature.
- Enabling the feature compiles the candidate implementation but does not
  change keys, addresses, transactions, wallets, blocks, or consensus rules.

```sh
cargo check --offline --features sqisign-candidate
```

## Activation gates

Do not activate SQIsign in consensus until all of these are complete:

1. NIST publishes a final standard and parameter/encoding specification.
2. The vendored implementation is updated and validated against final NIST
   known-answer tests.
3. Paqus assigns a versioned signature-scheme identifier.
4. Public-key, secret-key, and signature encodings use the final fixed sizes.
5. Address derivation and transaction/witness serialization are versioned.
6. Node, wallet, genesis, governance, QCash, and recovery paths support the
   same activation rule.
7. The change is activated through an explicit consensus/network upgrade with
   replay and downgrade protection.

Never replace the existing ML-DSA constants in place on an existing chain.
Introduce a versioned signature envelope and a coordinated activation height.

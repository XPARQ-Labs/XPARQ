# Independent security review handoff

Status: prepared for external review; **not independently reviewed**.

Working tree baseline: `d500f2a7e4d438be16cba2096686ebe43bcb4a54`.
Pin a reviewed commit before release. The SHA-256 inventory under `docs/audit/`
identifies submitted source; it is traceability, not an audit or a complete
dependency inventory.

Read [initial SLH review](SLH_AUDIT_2026-10-09.md),
[follow-up hardening](HARDENING_2026-10-09.md),
[fork provenance](../depend/slhdsa/slh-dsa/XPARQ_PATCHES.md),
[signature schemes](SIGNATURE_SCHEMES.md) and [ownership](OWNERSHIP.md).

Independently examine:

1. FIPS 205 parameters, SHAKE domain/rates, context handling, deterministic signing,
   encoding and NIST known answers. Compare local patches to the original crate,
   including buffer guards and Debug changes.
2. Seed derivation/entropy, secret copies and lifetimes, panic behavior and practical
   side channels. Review optional SHA2 separately before any consensus proposal.
3. Scheme/key/salt binding to ProgramId, chain-bound commitments, caller identity,
   replay resistance, deployed-program ownership and foreign UTXO/asset rejection.
4. VM/kernel separation, forged call frames, foreign storage, unaccounted coin,
   asset mint authority, resource bounds, rollback and panic atomicity.
5. Cache key completeness, tip/height/reorg invalidation, dependent pending calls,
   concurrency, hash collisions, stale database generations and persistence ordering.
   Confirm received blocks always take the complete consensus validation path.
6. Unique invalid signatures, forged encodings, low fees, many peers, heavy VM calls,
   snapshots and long replay. Assess sustained/per-peer CPU budgets beyond queue caps.

Reproduction:

```sh
cargo test --workspace --release --locked --offline
cargo test -p crypto --release --features slh-sha2-benchmark --locked --offline --lib --tests
cargo clippy -p kernel --all-targets --no-deps --locked --offline -- -D warnings
cargo check --workspace --all-targets --no-default-features --features node/devnet,wallet/devnet,xparq-devkit/devnet --locked --offline
```

Networking tests require local loopback permission. No real wallet, user private
key or live database is needed. NIST `.sk` fixtures are publicly published test keys.
Performance commands: [benches README](../benches/README.md).

Report severity, concrete preconditions, a reproducer, affected inventory/commit
and remediation. Distinguish inherited upstream limitations from local changes.
The separate reviewer must write their own conclusion and list unreviewed surfaces.

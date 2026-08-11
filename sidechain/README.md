# XPARQ Sidechain Workspace

Independent proof-of-stake sidechain scaffold for XPARQ.

This directory is its own Cargo workspace and is not a member of the root
XPARQ workspace. Its initial cryptographic profile is:

- SQIsign Level 5 signatures;
- FIPS 202 SHA3-256, matching XPARQ L1;
- 20-byte, lowercase Bech32 `x1...` dual-authorization addresses shaped like
  XPARQ L1 addresses;
- active wire and protocol format identifiers fixed at `1`.
- backed wXPQ accounting with finalized L1 deposit replay protection and
  burn-before-release withdrawal intents;
- fixed-supply user tokens created by permanently burning whole wXPQ at the
  initial rate of 100,000,000 token units per wXPQ;
- a VM-free native token program with a fixed chain-scoped Program ID,
  canonical instructions, dual-SQIsign authorization, nonces, and receipts.

SHA3-256 covers hashes defined by the sidechain protocol. SQIsign retains
the internal transcript hashing required by its own algorithm.

Build and test only this workspace with:

```bash
cargo check --workspace --locked
cargo test --workspace --locked
```

This is an experimental library scaffold. It does not yet contain networking,
storage, block execution, staking transitions, slashing, bridge verification,
an order book, an AMM, a general-purpose VM, or a production-ready finality protocol. See
[`../Sidechain.md`](../Sidechain.md) for the security boundary and remaining
work.

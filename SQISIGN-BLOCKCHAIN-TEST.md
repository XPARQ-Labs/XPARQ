# SQIsign Level 5 blockchain test mode

The local Paqus development chain uses SQIsign Level 5 as its default core
signature scheme:

```sh
cargo test
cargo build
cd ../node && cargo run --release
cd ../wallet && cargo run --release
```

In this mode:

- owner signatures use SQIsign Level 5;
- authorization signatures use a second SQIsign Level 5 key;
- public keys are 129 bytes, secret keys 705 bytes, and signatures 292 bytes;
- newly encoded wallet addresses use the reserved `PX` HRP;
- ML-DSA `P` addresses are rejected by the active address parser;
- the crypto-agility registry marks only SQIsign Level 5 active.

This is a development network, not a production activation. SQIsign is still a
NIST candidate. Its consensus and wallet wire formats are incompatible with the
ML-DSA chain.

Always use a fresh wallet, genesis, database, chain data directory, and isolated
network ports. Never open an existing ML-DSA database or connect this build to
the normal Paqus network. The retained ML-DSA research build can be selected
explicitly with `--no-default-features`; this does not convert SQIsign chain
data back to ML-DSA.

For safety, the feature-forwarding node defaults to
`./data/paqus-sqisign-level5-test`, and the wallet defaults to
`wallet-sqisign-level5-test.json`.

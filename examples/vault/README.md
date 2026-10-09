# Fixed payout contract

This example deploys XPVM v2 code that pays a fixed recipient from the contract's
own coin and asset shares whenever called. Anyone can trigger the payout; the
caller cannot change its recipient or amount. This is a fixed payout example,
not an owner-controlled withdrawal contract.

Build the bytecode using the recipient's **64-character hex Program ID**,
an existing asset ID, and amounts in base units. Wallet recipients can use
the value printed by `wallet program-id` directly:

```bash
python3 examples/vault/build.py --recipient-hex PROGRAM_ID_HEX --coin-units 100000000 --asset-id ASSET_ID --asset-units 200000000 --output /tmp/vault.xpvm
./target/debug/wallet program-deploy --code /tmp/vault.xpvm --nonce 1 --wallet wallet.json
```

Use the resulting `Program ID` to fund, inspect, and execute the contract:

```bash
./target/debug/wallet sign-spend --to program:PROGRAM_ID --amount 5 --wallet wallet.json
./target/debug/wallet program-transfer --asset ASSET_ID --to program:PROGRAM_ID --amount 10 --wallet wallet.json
./target/debug/wallet program-account --program-id PROGRAM_ID
./target/debug/wallet program-call --program-id PROGRAM_ID --wallet wallet.json
```

Confirm each funding transaction before calling the contract. The contract spends
only shares present before the invocation. The caller pays miner fees, protocol
burn, and VM fuel from their own wallet. A transfer selects at most 256 matching
shares in canonical ID order and returns change to the program. If either payout
cannot be funded, the entire invocation fails without changing balances or state.

See [XPVM](../../docs/XPVM.md) for format and protocol compatibility details.

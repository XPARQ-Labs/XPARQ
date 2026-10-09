# Program-owned asset issuer

This XPVM v3 example registers a native asset and mints a fixed amount to a fixed
recipient on every call. The executing program is both creator and mint authority.
The initial supply stays with the program. Registration is skipped after the first
successful call; subsequent calls mint with the next canonical nonce until the
lifetime issuance cap is reached. Calls are public.

Amounts below are base units (native assets use 8 decimals). Use the recipient's
32-byte Program ID as hex:

```bash
python3 examples/asset_issuer/build.py --recipient-hex PROGRAM_ID_HEX --name LAUNCH --max-supply-units 1100000000 --initial-mint-units 100000000 --mint-units 500000000 --output /tmp/asset_issuer.xpvm
./target/debug/wallet program-deploy --code /tmp/asset_issuer.xpvm --nonce 1 --wallet wallet.json
```

After deployment is confirmed, use the printed Program ID:

```bash
./target/debug/wallet program-call --program-id PROGRAM_ID --wallet wallet.json
./target/debug/wallet program-account --program-id PROGRAM_ID
```

The first confirmed call creates 1 unit for the program and mints 5 units to the
recipient. The second adds another 5 units, reaching the maximum of 11. The third
fails without changing asset supply, balances, or payment. Read the AssetContract
ID from the program account's asset shares and inspect the record using
`GET /program/asset/ASSET_ID`.

The program needs no coin deposit for issuance. The caller pays miner fees,
protocol/state burn and VM fuel. Quotes include both registration and mint growth;
subsequent quotes exclude registration growth. Payment and all proposed operations
commit atomically, and rollback restores the complete pre-call state.

This example supplies the issuance primitives for a launchpad. It has a fixed
recipient and amount; sale pricing, payment inspection, caller restrictions and
dynamic call arguments require additional VM instructions.

See [XPVM](../../docs/XPVM.md) for byte encoding and protocol compatibility.

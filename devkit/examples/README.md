# XPVM assembly examples

Build and validation commands are in the [devkit guide](../README.md).

| Source | Behavior | Invocation |
| --- | --- | --- |
| [counter.xpa](counter.xpa) | Public scalar increment; returns the new value | Empty calldata |
| [vault.xpa](vault.xpa) | Deployer-only deposits/withdrawals of the program's coin | Empty data for deposit; 16-byte LE u128 zeno for withdrawal |
| [asset-transfer.xpa](asset-transfer.xpa) | Deployer-only transfer of the program's existing asset shares | Empty calldata; ASSET/RECIPIENT/AMOUNT embedded at assembly time |
| [asset-transfer-many.xpa](asset-transfer-many.xpa) | Deployer-only asset distribution to multiple recipients | Borsh AssetContract + Vec<AssetOutput> calldata |

The vault checks authenticated **caller**, not a claimed owner in input bytes.
Calling through another program changes caller to that program and does not
inherit the deployer's authority. A positive withdrawal must fit the kernel's
coin amount limit and available balance. The recipient is always the deployer.
Only the deployer may call the deposit entry in this example; ordinary coin
transfers to the vault ProgramId can still fund it without executing the code.

To encode a 0.25 XPQ withdrawal, use 25,000,000 zeno:

```bash
python3 -c 'print((25000000).to_bytes(16, "little").hex())'
```

Pass the resulting hex to `run.py call --data HEX --program-id VAULT_ID`.
Asset transfers require funding the program with the selected asset first. Use
the devkit wallet's `program-transfer --asset ASSET --to PROGRAM_ID --amount N`
command, wait for confirmation, and then call the funded program. All kernel
ownership, supply, fee, burn, resource and atomicity checks remain authoritative.
The multioutput example accepts up to 82 recipients in one call. Encode its
calldata with `asset-transfer-many-payload.py`; amounts are raw asset units:

```bash
devkit/target/debug/xparq-devkit assemble \
  devkit/examples/asset-transfer-many.xpa -o /tmp/asset-transfer-many.xpvm
devkit/target/debug/wallet program-deploy \
  --code /tmp/asset-transfer-many.xpvm --nonce 1 --rpc 127.0.0.1:26666

DATA=$(python3 devkit/examples/asset-transfer-many-payload.py \
  --asset ASSET_ID \
  --output PROGRAM_ID_A=100000000 \
  --output PROGRAM_ID_B=250000000)
devkit/target/debug/wallet program-call \
  --program-id VAULT_ID --data "$DATA" --rpc 127.0.0.1:26666
```

The program combines the listed outputs into one asset transfer and returns any
change to itself. Its deployer check makes only the deployer able to trigger the
distribution.
Existing native asset creation/minting examples remain in
[examples/asset_issuer](../../examples/asset_issuer/README.md).

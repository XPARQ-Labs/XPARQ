# XPVM assembly examples

Build and validation commands are in the [devkit guide](../README.md).

| Source | Behavior | Invocation |
| --- | --- | --- |
| [counter.xpa](counter.xpa) | Public scalar increment; returns the new value | Empty calldata |
| [vault.xpa](vault.xpa) | Deployer-only deposits/withdrawals of the program's coin | Empty data for deposit; 16-byte LE u128 zeno for withdrawal |
| [asset-transfer.xpa](asset-transfer.xpa) | Deployer-only transfer of the program's existing asset shares | Empty calldata; ASSET/RECIPIENT/AMOUNT embedded at assembly time |

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
Existing native asset creation/minting examples remain in
[examples/asset_issuer](../../examples/asset_issuer/README.md).

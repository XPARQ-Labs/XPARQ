# Owner-controlled XPQ and asset vault

This example builds an XPVM v4 vault. The account that deploys it is the owner.
Every call checks that the authenticated immediate caller equals the deployer.
Only that owner can choose a recipient and transfer amount. The owner can send
funds to their own Program ID to claim them, or to another Program ID.

This vault transfers from its own balances; it does not keep per-user deposit
claims. Deposits must be sent to the vault's Program ID. Calls are atomic: if the
vault does not have enough matching funds, nothing is transferred. The caller
pays the call's protocol burn and miner fee.

## Build and deploy

From the repository root, create bytecode and deploy it with the wallet that
should own the vault:

```bash
python3 examples/vault/build.py --output /tmp/vault.xpvm
./target/release/wallet program-deploy \
  --code /tmp/vault.xpvm \
  --nonce 1 \
  --wallet wallet.json \
  --rpc 127.0.0.1:26666
```

Use a deployment nonce that this wallet owner has not used before. Record the
deployed `Program ID`; that's the address to which XPQ and assets should be sent.
Wait for the deployment and any funding transfers to be confirmed before calling
the vault.

## Transfer XPQ to yourself

Get the owner's 64-character Program ID with `wallet program-id`, then use it as
the recipient. The amount is in zeno (1 XPQ = 100,000,000 zeno):

```bash
OWNER_ID=YOUR_WALLET_PROGRAM_ID
DATA=$(python3 examples/vault/call.py coin \
  --recipient-hex "$OWNER_ID" --amount 100000000)
./target/release/wallet program-call \
  --program-id VAULT_PROGRAM_ID --data "$DATA" \
  --wallet wallet.json --rpc 127.0.0.1:26666
```

To send XPQ to another address, set `--recipient-hex` to that recipient's
Program ID. The connected wallet still must be the vault owner to authorize the
call.

## Transfer an asset

Asset amounts use the asset's base units. Provide the 64-character asset ID and
the recipient Program ID:

```bash
DATA=$(python3 examples/vault/call.py asset \
  --asset-id ASSET_ID --recipient-hex RECIPIENT_PROGRAM_ID --amount 250)
./target/release/wallet program-call \
  --program-id VAULT_PROGRAM_ID --data "$DATA" \
  --wallet wallet.json --rpc 127.0.0.1:26666
```

To claim the asset to yourself, use your wallet's Program ID as the recipient.
Inspect the vault's available balances with:

```bash
./target/release/wallet program-account --program-id VAULT_PROGRAM_ID \
  --rpc 127.0.0.1:26666
```

The bytecode checks the caller against the deployer before parsing transfer
data. A call through another program has that program as its immediate caller,
so it is rejected even if the original signer is the vault owner. This is an
example, not an audited custody contract; test on devnet before using real funds.

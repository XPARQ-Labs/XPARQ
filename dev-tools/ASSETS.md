# Native asset development

XPARQ assets are ledger-based fungible tokens implemented by the native asset
extension. Creating an asset is a permissionless transaction: a developer does
not need to submit a GitHub pull request, deploy WASM, or ask node operators to
rebuild their binaries.

## Create an asset

The wallet must already contain enough XPQ to pay the normal size-based miner
fee. Asset amounts are unsigned 128-bit integers expressed in base units.
`decimals` is display metadata and does not change the integer sent on-chain.

For a token named `Example Token`, symbol `EXT`, 8 decimals, a maximum supply
of 100 million display tokens, and an initial mint of 1 million display tokens:

```bash
cargo run -p wallet -- asset-register \
  --name "Example Token" \
  --symbol EXT \
  --decimals 8 \
  --max-supply 10000000000000000 \
  --initial-mint 100000000000000 \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

Registration and the initial mint are atomic. The signing address becomes the
mint authority and receives the initial balance. The command prints the
canonical 64-character `asset_id`; save that identifier for later operations.
The asset ID is deterministically derived from the creator address and symbol,
so the same creator cannot register the same symbol twice.

The accepted metadata is:

- name: 1-64 printable ASCII characters;
- symbol: 1-16 ASCII letters or digits, normalized to uppercase;
- decimals: 0-18;
- maximum supply and initial mint: positive `u128` base-unit integers;
- initial mint: no greater than maximum supply.

## Query state

```bash
cargo run -p wallet -- asset-info \
  --asset ASSET_ID \
  --rpc 127.0.0.1:6666

cargo run -p wallet -- asset-balance \
  --asset ASSET_ID \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

To query another address, replace `--wallet wallet.json` with
`--address 0x...`. The equivalent RPC routes are:

```text
GET /asset/{asset_id}
GET /asset/{asset_id}/balance/{address}
GET /asset/nonce/{address}
GET /account/{address}
```

The account response includes the address's asset IDs and balances. Exact
`u128` values are JSON strings so clients do not lose integer precision.

## Mint, transfer, and burn

Only the original mint authority may mint. Supply can never exceed
`max_supply`.

```bash
cargo run -p wallet -- asset-mint \
  --asset ASSET_ID --to 0xRECIPIENT --amount 500000000 \
  --wallet wallet.json --rpc 127.0.0.1:6666

cargo run -p wallet -- asset-transfer \
  --asset ASSET_ID --to 0xRECIPIENT --amount 250000000 \
  --wallet wallet.json --rpc 127.0.0.1:6666

cargo run -p wallet -- asset-burn \
  --asset ASSET_ID --amount 100000000 \
  --wallet wallet.json --rpc 127.0.0.1:6666
```

Mint credits the selected recipient, transfer debits the signer and credits
the recipient, and burn destroys units owned by the signer. Each operation is
one signed extension transaction and pays its own XPQ miner fee. It also burns
XPQ for persistent state created by that call: registration accounts for the
metadata, supply, creator balance, and first nonce entries; mint or transfer
accounts for a recipient balance entry when one does not already exist; and a
signer's first asset call accounts for its nonce entry. Existing-entry updates
do not pay state-creation burn, and deletion does not receive a refund.

## Current asset model

The native model deliberately provides fixed metadata, one immutable mint
authority, supply accounting, balances, mint, burn, and transfer. It does not
yet support authority rotation, freezing, allowlists, royalties, token-specific
hooks, or contract-controlled balances. Those policies belong in a future WASM
application model rather than being added as new core primitives.

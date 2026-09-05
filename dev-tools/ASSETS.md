# Native asset development

XPARQ assets are ledger-based fungible tokens implemented directly by the
Layer-1 ledger. Creating an asset is a permissionless native transaction: a developer does
not need to submit a GitHub pull request, deploy WASM, or ask node operators to
rebuild their binaries.

## Create an asset

The wallet must already contain enough XPQ to pay the normal size-based miner
fee. CLI asset amounts use the human decimal denomination declared by
`decimals`; the wallet converts them to exact unsigned 128-bit `Unit` values
before signing.

For a token named `Example Token`, symbol `EXT`, 8 decimals, a maximum supply
of 100 million display tokens, and an initial mint of 1 million display tokens:

```bash
cargo run -p xparq-wallet -- asset-register \
  --name "Example Token" \
  --symbol EXT \
  --decimals 8 \
  --max-supply 100000000 \
  --initial-mint 1000000 \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

Registration and the initial mint are atomic. The signing address becomes the
mint authority and receives the initial balance. The command prints the
canonical `asset:`-prefixed `asset_id` followed by 64 lowercase hexadecimal
characters; save that identifier for later operations. The asset ID is
deterministically derived from the creator address and symbol under the
`xparq:asset-id:v1` domain, so the same creator cannot register the same symbol
twice.

The accepted metadata is:

- name: 1-64 printable ASCII characters;
- symbol: 1-16 ASCII letters or digits, normalized to uppercase;
- decimals: 0-18;
- maximum supply and initial mint: positive decimal amounts with no more than
  the declared number of fractional digits;
- initial mint: no greater than maximum supply.

## Query state

```bash
cargo run -p xparq-wallet -- asset-info \
  --asset ASSET_ID \
  --rpc 127.0.0.1:6666

cargo run -p xparq-wallet -- asset-balance \
  --asset ASSET_ID \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

To query another address, replace `--wallet wallet.json` with
`--address Qx...`. The equivalent RPC routes are:

```text
GET /asset/{asset_id}
GET /asset/{asset_id}/balance/{address}
GET /asset/nonce/{address}
GET /account/{address}
```

The account response includes asset metadata and the address-owned shares.
Exact canonical `u128` values remain JSON strings so clients do not lose
integer precision; the wallet formats them using asset decimals.

## Mint, transfer, and burn

Only the original mint authority may mint. Supply can never exceed
`max_supply`.

```bash
cargo run -p wallet -- asset-mint \
  --asset ASSET_ID --to QxRECIPIENT --amount 5 \
  --wallet wallet.json --rpc 127.0.0.1:6666

cargo run -p wallet -- asset-transfer \
  --asset ASSET_ID --to QxRECIPIENT --amount 2.5 \
  --wallet wallet.json --rpc 127.0.0.1:6666

cargo run -p wallet -- asset-burn \
  --asset ASSET_ID --amount 1 \
  --wallet wallet.json --rpc 127.0.0.1:6666
```

Mint creates a share for the selected recipient, transfer consumes shares owned
by the signer and creates recipient/change shares, and burn destroys the units
in signer-owned shares. Transfer, deposit, and burn select shares through RPC.
Because burn has no change output, its amount must exactly match selected shares. Every
operation pays its XPQ miner fee and exact state/history burn. Registration and
mint are native asset operations, while user transfers use `Spend::Asset`.

Asset metadata preserves the original `creator` address independently from the
optional `mint_authority`. The creator never changes; `mint_authority: null`
represents an asset for which no further minting is authorized.

## Current asset model

The native model deliberately provides fixed metadata, one immutable mint
authority, supply accounting, balances, mint, burn, and transfer. It does not
yet support authority rotation, freezing, allowlists, royalties, token-specific
hooks, or contract-controlled balances. Those policies belong in a future WASM
application model rather than being added as new core primitives.

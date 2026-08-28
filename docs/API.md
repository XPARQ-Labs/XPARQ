# XPARQ Node RPC API

The node exposes an unauthenticated HTTP RPC intended for loopback or a trusted
private network. Run the node and open `/docs` for the interactive API reference,
or fetch `/openapi.json` for tooling and SDK generation.

Amounts are unsigned integer **esca**. `1,000,000 esca = 1 XPQ`.

Addresses use exactly 50 lowercase characters: `0x`, 40 hexadecimal characters
for the 20-byte address, and eight hexadecimal characters for its four-byte
domain-separated SHA3-256 checksum. Bech32 and raw hexadecimal addresses without
the checksum are rejected.

## Transaction submission

`POST /transaction` does not accept JSON. Its body is the canonical Borsh
encoding of `AuthorizedTransaction` with content type
`application/octet-stream`. Generate it with the XPARQ transaction and codec
crates, or use the wallet's `--offline` output.

```bash
curl -X POST \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @transaction.borsh \
  http://127.0.0.1:6666/transaction
```

The response contains the accepted transaction ID:

```json
{"transaction_id":"<64 lowercase hexadecimal characters>"}
```

Extension asset transactions use the same endpoint and canonical encoding. The
node exposes `GET /asset/nonce/{address}`, `GET /asset/{asset_id}`, and
`GET /asset/{asset_id}/balance/{address}` for builders and state queries. Asset
amounts are integer base units defined by each asset's `decimals` metadata.
Asset supply, limits, and balances are `u128` and therefore appear in JSON as
decimal strings rather than potentially lossy JSON numbers.
Every asset mutation carries a signed nonce-protected call plus an authorized
XPQ miner-fee spend; both transitions commit or roll back together.
Confirmed asset transaction responses decode the canonical payload and expose
`asset_id`, signer, nonce, and the register/mint/burn/transfer action. Account
responses include an `assets` array with ID, name, symbol, decimals, and exact
decimal-string balance; mint authorities see newly registered zero-balance
assets as well.

## Compatibility

Coin IDs returned by the account RPC and accepted by the wallet use the
case-sensitive `XPQ:` prefix followed by 64 hexadecimal characters. Account
UTXOs expose `maturity_height`: it is a height for immature block emissions and
`null` for ordinary transaction outputs. All five signature profiles are active
from genesis.

The interactive `/docs` page loads its renderer from a public CDN. The
`/openapi.json` specification itself is embedded in the node binary and remains
available without internet access.

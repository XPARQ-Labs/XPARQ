# XPARQ Node RPC API

The node exposes unauthenticated HTTP RPC intended for loopback or a trusted
private network. Interactive documentation is served at `/docs`; the embedded
OpenAPI specification is available at `/openapi.json`.

Native amounts are integer zeno. `1,000,000 zeno = 1 XPQ`. The miner relay fee
is node policy and is separate from the mandatory protocol burn. `GET
/fee-policy` reports both policies.

`POST /transaction` accepts canonical Borsh `AuthorizedTransaction` bytes with
content type `application/octet-stream`; it does not accept JSON.

Account and Coin endpoints include `/status`, `/fee-policy`,
`/balance/{address}`, `/account/{address}`, `/block/{height}`,
`/blocks/latest`, and the explorer routes. Native asset endpoints are
`/asset/nonce/{address}`, `/asset/{asset_id}`, and
`/asset/{asset_id}/balance/{address}`.

Asset IDs use the strict `asset:` prefix followed by 64 lowercase hexadecimal
characters. Asset quantities and supply are canonical `u128` values returned
as decimal JSON strings. Coin and asset-share ownership is address-only. Asset
metadata records the permanent creator separately from its optional account
mint authority.

The former extension transaction, extension-owned UTXO, WASM execution,
deployment, preview, nonce, and query APIs have been removed.

## Compatibility

Coin IDs use the case-sensitive `XPQ:` prefix followed by 64 hexadecimal
characters. Addresses use the canonical checksummed `Qx` text form. All five
signature profiles are active from genesis.

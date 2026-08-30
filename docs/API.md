# XPARQ Node RPC API

Developer tutorials for native assets and WASM extensions are available under
[`dev-tools/`](../dev-tools/README.md).

`GET /balance/{address}` returns total, available, reserved, UTXO count, and
asset balances in one node snapshot. Wallet balance display uses this endpoint
and therefore does not race against blocks while traversing paginated UTXOs.
`GET /account/{address}` remains the paginated UTXO endpoint used by the tracker
and transaction input selection.

The node exposes an unauthenticated HTTP RPC intended for loopback or a trusted
private network. Run the node and open `/docs` for the interactive API reference,
or fetch `/openapi.json` for tooling and SDK generation.

Native amounts are integer **zeno**. `1,000,000 zeno = 1 XPQ`.
Consensus currently encodes each native XPQ amount as an eight-byte
little-endian `u64`; arithmetic is checked.

`GET /fee-policy` exposes both the miner relay fee and the consensus state-burn
policy. A transaction that creates more persistent state than it deletes must
include exactly one `OutputTarget::Burn` for the required amount:

`created_weight * STATE_BURN_RATE_ZENO_PER_WEIGHT`

The reset-chain rate is `1 zeno` per state-weight unit. Coin and QCash UTXO
weights, plus the algorithm identifier, are committed by the chain-spec hash.
Consumed inputs do not receive burn credit. Burn outputs conserve transaction
value during validation but are deliberately not inserted into the UTXO set.
Native asset calls charge the canonical key-plus-value size of every new
persistent extension entry. Registration creates metadata, supply, creator
balance, and (on the creator's first asset call) nonce entries. Mint and
transfer additionally charge a recipient balance entry only when that entry
does not already exist; a signer's first asset call creates its nonce entry.
Updating an existing supply, balance, or nonce entry is not charged as state
creation, and deleting an entry does not grant a refund.
The canonical ledger stores a checked `total_burned` accumulator. It increases
when a burn output is applied, decreases on rollback or reorg, persists in the
database and snapshots, and is exposed by `GET /status` in zeno.

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
decimal-string balance. Registration includes a nonzero initial mint credited
atomically to the creator address; subsequent distribution uses asset transfer.

Permissionless WASM deployment also uses `POST /transaction`. Wallets obtain
the signed deployment nonce from `GET /wasm/nonce/{address}` and can query the
immutable manifest and automatic activation status from
`GET /wasm/{extension_id}`.

## Compatibility

Coin IDs returned by the account RPC and accepted by the wallet use the
case-sensitive `XPQ:` prefix followed by 64 hexadecimal characters. Coin UTXOs
have no maturity field; block-emission outputs follow the same ownership rules
as ordinary outputs. The RPC only marks inputs reserved by the local mempool.
All five signature profiles are active from genesis.

The interactive `/docs` page loads its renderer from a public CDN. The
`/openapi.json` specification itself is embedded in the node binary and remains
available without internet access.

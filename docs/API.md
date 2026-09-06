# XPARQ Node RPC API

Developer tutorials for native assets and WASM extensions are available under
[`dev-tools/`](../dev-tools/README.md).

`GET /balance/{address}` returns total, available, reserved, UTXO count, and
asset balances in one node snapshot. Wallet balance display uses this endpoint
and therefore does not race against blocks while traversing paginated UTXOs.
`GET /account/{address}` remains the paginated UTXO endpoint used by the tracker
and transaction input selection. Every page includes `utxo_snapshot`, a digest
of that address's Coin UTXOs, mempool reservations, and signature profile.
Wallets paginate with the opaque `next_utxo_cursor`/`utxo_after` CoinId cursor
instead of an array offset. Concurrent incoming mining rewards therefore do not
shift page positions or force mining to stop; newly inserted IDs behind the
cursor can safely wait for the next scan.

The node exposes an unauthenticated HTTP RPC intended for loopback or a trusted
private network. Run the node and open `/docs` for the interactive API reference,
or fetch `/openapi.json` for tooling and SDK generation.

Native amounts are integer **zeno**. `1,000,000 zeno = 1 XPQ`.
Consensus currently encodes each native XPQ amount as an eight-byte
little-endian `u64`; arithmetic is checked.

`GET /fee-policy` exposes both the miner relay fee and the consensus state-burn
policy. A transaction that creates persistent canonical state must include
exactly one `OutputTarget::Burn` for the required amount:

`(canonical_transaction_size + positive_net_state_growth_weight) * 1 zeno`

The consensus rate is fixed at `1 zeno` per canonical transaction byte or
state-weight unit. The complete authorized transaction encoding is permanent
canonical history. Positive net Coin UTXO growth, first-time account profile
keys, asset entries, and extension/WASM key-value entries are also charged.
Consumed Coin UTXOs offset Coin outputs only in the state-growth component;
they do not erase archival transaction bytes and cannot produce a refund.
Updates to existing non-Coin entries and deleted state receive no credit. The
active rate, Coin UTXO weight, archival block size, and miner protocol burns are
exposed by `/fee-policy`; the algorithm and parameters are committed by the
chain-spec hash.
The miner relay fee is node/miner policy and is separate from this mandatory
protocol burn. Consumed inputs do not receive burn credit. Burn outputs conserve transaction
value during validation but are deliberately not inserted into the UTXO set.
No canonical state-creating operation is exempt: Coin and asset transactions,
extension calls, WASM deployment, and block emission account for the history
and positive state growth they create. Consensus requires exactly one burn
output with the exact amount when
the required burn is nonzero; missing, underpaid, overpaid, or duplicate burn
outputs are rejected. Each non-genesis block additionally creates a fixed
canonical archival record and one emission Coin UTXO. Their combined protocol burn
is deducted from the gross subsidy before the miner emission UTXO is stored.
Native asset calls charge the canonical key-plus-value size of every new
persistent extension entry. Registration creates metadata, supply, creator
balance, and (on the creator's first asset call) nonce entries. Mint and
transfer additionally charge a recipient balance entry only when that entry
does not already exist; a signer's first asset call creates its nonce entry.
Updating an existing supply, balance, or nonce entry is not charged as state
creation, and deleting an entry does not grant a refund.
The canonical ledger stores a checked `total_burned` accumulator. It increases
when an explicit coin burn action is applied, decreases on rollback or reorg, persists in the
database and snapshots, and is exposed by `GET /status` in zeno.
Block explorer responses distinguish the gross `subsidy`, `state_burn`, and
net `miner_emission`.

Block responses keep `transactions` as the non-emission transaction count and
also expose `transaction_ids` plus `transaction_details`. Each detail contains
the transaction ID, type, canonical byte size, decoded transaction outputs, and
the explicit burn amount where applicable.

Explorer transaction outputs expose the canonical target as `type` (`address`,
`miner`, or `extension`), the integer `amount`, and `unit: "zeno"`. The derived
`role` is `recipient`, `change`, `miner_fee`, or `extension_deposit`. `change` means an
address output returns to the declared transaction sender; it is an explorer
interpretation and does not add a Change primitive to consensus.

Addresses use exactly 50 characters: the case-sensitive `Qx` prefix, 40
lowercase hexadecimal characters for the 20-byte address, and eight hexadecimal
characters for its four-byte domain-separated SHA3-256 checksum. Bech32 and raw
hexadecimal addresses without the checksum are rejected.

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

Native Layer-1 asset transactions use the same endpoint and canonical encoding. The
node exposes `GET /asset/nonce/{address}`, `GET /asset/{asset_id}`, and
`GET /asset/{asset_id}/balance/{address}` for builders and state queries. Asset
IDs use the canonical `asset:` prefix followed by exactly 64 lowercase
hexadecimal characters. Amounts are integer base units defined by each asset's
`decimals` metadata.
Asset supply, limits, and balances are `u128` and therefore appear in JSON as
decimal strings rather than potentially lossy JSON numbers.
Metadata records the permanent `creator` separately from the optional
`mint_authority`; a missing mint authority is returned as JSON `null`.
Every asset mutation carries a nonce-protected call authorized through the same
reveal-or-known account-key registry used by XPQ, plus an authorized
XPQ miner-fee spend; both transitions commit or roll back together.
Confirmed asset transaction responses decode the canonical payload and expose
`asset_id`, signer, nonce, and the register/mint/burn/transfer action. Account
responses include an `assets` array with ID, name, symbol, decimals,
`max_supply`, total `mint`, and the account-owned `shares`. Ownership amounts
exist on those shares rather than as a duplicate asset-level balance field.
Registration includes a nonzero initial mint credited atomically to the creator
address; subsequent distribution uses asset transfer.

Permissionless WASM deployment also uses `POST /transaction`. Wallets obtain
the signed deployment nonce from `GET /wasm/nonce/{address}` and can query the
immutable manifest, automatic activation status, aggregate coin balance in
zeno, and owned coin UTXO count from `GET /wasm/{extension_id}`.
Extension IDs use the case-sensitive `extension:` prefix followed by exactly
64 lowercase hexadecimal characters.

Generic signed WASM application calls are active from genesis. Their nonce is
scoped by extension and signer and is available from
`GET /wasm-app/nonce/{extension_id}/{address}`. `POST /extension/preview`
accepts a canonical Borsh `ExtensionCall` and returns the next height, exact
new persistent-state weight, and required XPQ state burn. The preview covers
the full new key-plus-value state produced by WASM deploy or execution,
including the first host-owned nonce entry; updating existing state is not
charged again. The preview can become stale if another transaction changes the
same state before inclusion, in which case the transaction must be rebuilt.

The WASM host API supports native-value custody. A Coin output created with
`OutputTarget::Extension(extension_hash)` is owned by that extension, while an
asset `TransferToExtension` credits its extension asset balance. During apply,
the authenticated extension may emit `coin_transfer` to an account,
`coin_transfer_extension` to another extension, `coin_burn` to burn coin,
`asset_transfer` to send asset shares, or `asset_burn` to burn asset shares.
The ledger supplies the executing
`ExtensionHash`; guest payloads cannot choose the debit authority. All effects,
extension state, fees, Coin change, and asset balances commit or roll back as
one transition.

The `block_weight` field is the canonical serialized block size plus the
consensus WASM execution reservation. Every WASM call reserves
`ceil(manifest.fuel_limit / 4)` weight units, while host operations consume an
additional 32 fuel plus 1 fuel per byte read, written, deleted, or passed to a
native-value effect. The 5 MiB block limit applies to the combined weight.
State access uses a write overlay over the existing namespace, so execution
does not copy all extension state for each call.

## Compatibility

Coin IDs returned by the account RPC and accepted by the wallet use the
case-sensitive `XPQ:` prefix followed by 64 hexadecimal characters. Coin UTXOs
have no maturity field; block-emission outputs follow the same ownership rules
as ordinary outputs. The RPC only marks inputs reserved by the local mempool.
All five signature profiles are active from genesis.

The interactive `/docs` page loads its renderer from a public CDN. The
`/openapi.json` specification itself is embedded in the node binary and remains
available without internet access.

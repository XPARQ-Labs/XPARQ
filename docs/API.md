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

Native amounts are integer **zeno**. `100,000 zeno = 1 XPQ`.
Consensus currently encodes each native XPQ amount as an eight-byte
little-endian `u64`; arithmetic is checked.

`GET /fee-policy` exposes both the miner relay fee and the consensus state-burn
policy. A transaction that creates persistent canonical state must include
exactly one `OutputTarget::Burn` for the required amount:

`(canonical_transaction_size + created_state_weight) * 1 zeno`

The consensus rate is fixed at `1 zeno` per newly created canonical byte or
state-weight unit. The complete authorized transaction encoding is charged as
permanent canonical history. Coin UTXOs, QCash UTXOs, first-time account profile-key
registrations, asset entries, and extension/WASM key-value entries are charged.
Updates to existing entries and deleted state receive no charge or credit.
The active rate, Coin and QCash UTXO weights, and emission-UTXO burn are
exposed by `/fee-policy`; the algorithm and parameters are committed by the
chain-spec hash.
The miner relay fee is node/miner policy and is separate from this mandatory
protocol burn. Consumed inputs do not receive burn credit. Burn outputs conserve transaction
value during validation but are deliberately not inserted into the UTXO set.
No canonical state-creating operation is exempt: on-chain spend, QCash
withdraw/redeem/split/merge, extension calls, WASM deployment, and block
emission all account for every Coin, QCash, or extension-state entry they
create. Consensus requires exactly one burn output with the exact amount when
the required burn is nonzero; missing, underpaid, overpaid, or duplicate burn
outputs are rejected. Transferring a QCash bearer file offline does not mutate
canonical state and therefore is not an on-chain operation subject to burn.
Each non-genesis block additionally creates a fixed 153-weight canonical block
record and one 60-weight emission Coin UTXO. Their combined 213-zeno state burn
is deducted from the gross subsidy before the miner emission UTXO is stored.
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
Each non-genesis block emission also creates one Coin UTXO. Consensus deducts
one `COIN_UTXO_STATE_WEIGHT` charge from the scheduled gross subsidy before the
miner UTXO is inserted and adds that amount to `total_burned`. Block explorer
responses distinguish the gross `subsidy`, `state_burn`, and net
`miner_emission`.

Block responses keep `transactions` as the non-emission transaction count and
also expose `transaction_ids` plus `transaction_details`. Each detail contains
the transaction ID, type, canonical byte size, and decoded transaction outputs,
including miner fee and state-burn outputs where applicable.

Explorer transaction outputs expose the canonical target as `type` (`address`,
`miner`, or `burn`), the integer `amount`, and `unit: "zeno"`. The derived
`role` is `recipient`, `change`, `miner_fee`, or `state_burn`. `change` means an
address output returns to the declared transaction sender; it is an explorer
interpretation and does not add a Change primitive to consensus.

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
responses include an `assets` array with ID, name, symbol, decimals, and exact
decimal-string balance. Registration includes a nonzero initial mint credited
atomically to the creator address; subsequent distribution uses asset transfer.

Permissionless WASM deployment also uses `POST /transaction`. Wallets obtain
the signed deployment nonce from `GET /wasm/nonce/{address}` and can query the
immutable manifest and automatic activation status from
`GET /wasm/{extension_id}`.

Generic signed WASM application calls are active from genesis. Their nonce is
scoped by extension and signer and is available from
`GET /wasm-app/nonce/{extension_id}/{address}`. `POST /extension/preview`
accepts a canonical Borsh `ExtensionCall` and returns the next height, exact
new persistent-state weight, and required XPQ state burn. The preview covers
the full new key-plus-value state produced by WASM deploy or execution,
including the first host-owned nonce entry; updating existing state is not
charged again. The preview can become stale if another transaction changes the
same state before inclusion, in which case the transaction must be rebuilt.

WASM ABI version 2 supports native-value custody. A Coin output created with
`OutputTarget::Extension(extension_hash)` is owned by that extension, while an
asset `TransferToExtension` credits its extension asset balance. During apply,
the authenticated extension may emit `coin_transfer` or `asset_transfer` to
send its own holdings to an account. The ledger supplies the executing
`ExtensionHash`; guest payloads cannot choose the debit authority. All effects,
extension state, fees, Coin change, and asset balances commit or roll back as
one transition.

## Compatibility

Coin IDs returned by the account RPC and accepted by the wallet use the
case-sensitive `XPQ:` prefix followed by 64 hexadecimal characters. Coin UTXOs
have no maturity field; block-emission outputs follow the same ownership rules
as ordinary outputs. The RPC only marks inputs reserved by the local mempool.
All five signature profiles are active from genesis.

The interactive `/docs` page loads its renderer from a public CDN. The
`/openapi.json` specification itself is embedded in the node binary and remains
available without internet access.

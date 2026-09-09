# XPARQ Wallet

`wallet/` contains the reusable `xparq-wallet` library and the `wallet`
executable. It never opens node storage and communicates through HTTP RPC.

```bash
cargo build --release --locked -p xparq-wallet
./target/release/wallet
./target/release/wallet --help
```

The interactive menu supports wallet creation and restoration, balances,
canonical history, UTXO tracking and consolidation, XPQ sends, native assets,
and block exploration.

## Security

The wallet file contains recovery and private signing material. It is checked
for internal consistency when loaded, created atomically, and given owner-only
permissions on Unix. Back up the mnemonic offline and never commit, upload, or
share the wallet file. A miner needs only the public payout address. Keep plain
HTTP RPC on loopback or a trusted private network.

## XPQ transactions

Signed transactions are submitted automatically to `/transaction`. Use
`--offline` to print canonical transaction bytes without contacting a node.

```bash
./target/release/wallet sign-spend --to ADDRESS --amount 1 --rpc 127.0.0.1:6666
./target/release/wallet consolidate --wallet wallet.json --rpc 127.0.0.1:6666
```

Without explicit inputs, the wallet selects available `/account/{address}`
UTXOs and creates change. Consolidation merges the selected XPQ UTXOs into one
self-owned output. Consensus validates it as an ordinary transaction, so its
canonical bytes still incur archival burn and a miner fee.

The miner fee is node policy. The protocol burn separately covers canonical
transaction history and positive net state growth. Consumed Coin UTXOs offset
new Coin UTXOs for state growth but do not erase historical transaction bytes.

## Native assets

Asset quantities are stored canonically as integer `Unit` values. Wallet input
and output use the human denomination declared by `decimals`; for example,
`1.25` with `decimals=8` becomes `125000000 Unit`. The wallet summary shows
`max_supply` and total `mint`; ownership remains represented by the listed
shares instead of a duplicate asset-level balance. Registration derives a canonical
asset identifier and atomically credits a nonzero initial mint to an
`AssetShare` owned by the creator. Each share has a hexadecimal identifier, retains
its parent `AssetHash`, and is owned by an address.

```bash
./target/release/wallet asset-register --name "Gold Token" --symbol GOLD --decimals 2 --max-supply 10000 --initial-mint 1000
./target/release/wallet asset-mint --asset ID --to ADDRESS --amount 5.50
./target/release/wallet asset-transfer --asset ID --to ADDRESS --amount 2.25
./target/release/wallet asset-burn --asset ID --amount 1
./target/release/wallet asset-info --asset ID
./target/release/wallet asset-balance --asset ID
```

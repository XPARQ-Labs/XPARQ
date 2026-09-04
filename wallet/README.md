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
WASM extensions, and block exploration.

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
UTXOs and creates change. Consolidation spends all available XPQ UTXOs into one
self-owned output. Consensus validates it as an ordinary transaction, so its
canonical bytes still incur archival burn and a miner fee.

The miner fee is node policy. The protocol burn separately covers canonical
transaction history and positive net state growth. Consumed Coin UTXOs offset
new Coin UTXOs for state growth but do not erase historical transaction bytes.

## Native assets

Asset quantities are integer `Unit` values. Registration derives a canonical
`asset:` identifier and atomically credits a nonzero initial mint to an
`AssetShare` owned by the creator. Each share has a `share:` identifier, retains
its parent `AssetHash`, and may be owned by an address or extension.

```bash
./target/release/wallet asset-register --name "Gold Token" --symbol GOLD --decimals 2 --max-supply 1000000 --initial-mint 1000000
./target/release/wallet asset-mint --asset ID --to ADDRESS --amount 500
./target/release/wallet asset-transfer --asset ID --to ADDRESS --amount 25
./target/release/wallet asset-deposit --asset ID --extension EXTENSION_ID --amount 25
./target/release/wallet asset-burn --asset ID --amount 10
./target/release/wallet asset-info --asset ID
./target/release/wallet asset-balance --asset ID
```

## WASM extensions

```bash
./target/release/wallet wasm-deploy --name example.state --wasm module.wasm
./target/release/wallet wasm-info --extension ID
./target/release/wallet wasm-call --extension ID --payload-file call.bin
```

Deployments are immutable and activate after the consensus delay. The wallet
previews newly created persistent state and includes its exact protocol burn.
Extension-owned coin and asset transfers are authenticated against the
executing extension and apply atomically with extension state.

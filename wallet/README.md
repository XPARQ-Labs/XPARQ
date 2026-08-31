# XPARQ Wallet

`wallet/` contains the reusable wallet library and `wallet` executable. It
never opens node storage and communicates through HTTP RPC.

```bash
cargo build --release --locked -p wallet
./target/release/wallet
./target/release/wallet --help
```

The interactive menu supports creation/restoration, balance, canonical
history, UTXO tracking, XPQ sends, QCash operations, native asset creation and
management, and block exploration.

## Security

`wallet.json` contains the recovery mnemonic, profile public key, and 32-byte
private signing seed in hexadecimal plaintext. The keys are checked against the
mnemonic and selected signature profile whenever the wallet is loaded. New
files are created atomically, never overwritten, and use owner-only `0600`
permissions on Unix. Back up the mnemonic offline and never commit wallet
files. A miner needs only the public payout address.

QCash files are plaintext Falcon-512 bearer credentials. Whoever possesses a
valid unspent file can spend it. The `XPQCASH1` format includes a
domain-separated checksum and is written with `0600` permissions on Unix.
Canonical filenames contain the amount (`10XPQ.QCash`); additional files with
the same amount are numbered (`10XPQ(2).QCash`, `10XPQ(3).QCash`, and so on).

## Transactions

Signed transactions are submitted automatically to `/transaction`. Supply
`--offline` to print canonical transaction hex without contacting a node:

```bash
./target/release/wallet sign-spend --to ADDRESS --amount 1 --rpc 127.0.0.1:6666
./target/release/wallet sign-spend --to ADDRESS --amount 1 --offline
```

Without `--input`, the wallet reads paginated `/account/<address>` UTXOs,
selects available inputs, and creates change. Successful submission prints the
transaction ID and canonical serialized size.

Partial redeem sends the requested XPQ and creates fresh QCash change. Split
accepts one requested amount when the remainder becomes its second output.
Merge consumes at least two inputs.

```bash
./target/release/wallet sign-withdraw --qcash 100 --cash-dir cash
./target/release/wallet qcash-split --file cash/FILE.QCash --qcash 60 --cash-dir cash
./target/release/wallet qcash-merge --file cash/A.QCash --file cash/B.QCash --cash-dir cash
./target/release/wallet qcash-redeem --file cash/FILE.QCash --to ADDRESS --amount 40 --cash-dir cash
```

The wallet automatically adds a `BlockMiner` output paying `1 zeno` per
canonical transaction byte. There is no manual fee prompt or `--miner` fee
option. For QCash redeem, split, and merge, this fee is deducted from the
QCash value; ordinary spend and withdraw select enough XPQ input value for it.
The wallet also adds an exact `Burn` output for every persistent state entry a
transaction creates. Consumed inputs do not receive burn credit. The state-burn
rate and UTXO weights are consensus parameters returned by `GET /fee-policy`.
The balance screen also reports the chain-wide cumulative XPQ burned supply
from the canonical ledger's `GET /status` response. This value is a network
metric and is separate from the selected wallet's balance.

## Extension assets

Asset amounts are integer base units. Registration derives a deterministic
asset ID and makes the signing wallet its mint authority. Amounts and supply
limits accept the full unsigned 128-bit integer range.

```bash
./target/release/wallet asset-register --name "Gold Token" --symbol GOLD --decimals 2 --max-supply 1000000 --initial-mint 1000000
./target/release/wallet asset-mint --asset ID --to ADDRESS --amount 500
./target/release/wallet asset-transfer --asset ID --to ADDRESS --amount 25
./target/release/wallet asset-burn --asset ID --amount 10
./target/release/wallet asset-info --asset ID
./target/release/wallet asset-balance --asset ID
```

Register, mint, burn, and transfer are signed with the wallet profile and use a
per-signer nonce. The wallet selects XPQ inputs and pays the canonical-byte fee
inside the same atomic extension transaction.

## WASM extensions

```bash
./target/release/wallet wasm-deploy --name example.state --wasm module.wasm
./target/release/wallet wasm-info --extension ID
./target/release/wallet wasm-call --extension ID --payload-file call.bin
```

Permissionless deploys are immutable and activate 100 blocks after inclusion.
Generic signed calls, their signer nonce, and persistent-state burn are active
from genesis. The wallet previews all new persistent WASM state and adds its
exact consensus burn automatically.

Output bearer files are saved before submission so private signing material
cannot be lost. Keep every input file until canonical confirmation; never
print, upload, or share `.QCash` contents. Keep plain HTTP RPC on loopback or a
trusted private network.

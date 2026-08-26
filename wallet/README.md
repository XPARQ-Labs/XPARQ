# XPARQ Wallet

`wallet/` contains the reusable wallet library and `wallet` executable. It
never opens node storage and communicates through HTTP RPC.

```bash
cargo build --release --locked -p wallet
./target/release/wallet
./target/release/wallet --help
```

The interactive menu supports creation/restoration, balance, canonical
history, UTXO tracking, XPQ sends, QCash operations, and block exploration.

## Security

`wallet.json` contains the recovery mnemonic in plaintext. New files are
created atomically, never overwritten, and use owner-only `0600` permissions
on Unix. Back up the mnemonic offline and never commit wallet files. A miner
needs only the public payout address.

QCash files are plaintext ML-DSA-44 bearer credentials. Whoever possesses a
valid unspent file can spend it. The `XPQCASH1` format includes a
domain-separated checksum and is written with `0600` permissions on Unix.

## Transactions

Signed transactions are submitted automatically to `/transaction`. Supply
`--offline` to print canonical transaction hex without contacting a node:

```bash
./target/release/wallet sign-spend --to ADDRESS --amount 1 --expiry HEIGHT --rpc 127.0.0.1:6666
./target/release/wallet sign-spend --to ADDRESS --amount 1 --expiry HEIGHT --offline
```

Without `--input`, the wallet reads paginated `/account/<address>` UTXOs,
selects spendable inputs, and creates change. Successful submission prints the
transaction ID and canonical serialized size.

Partial redeem sends the requested XPQ and creates fresh QCash change. Split
accepts one requested amount when the remainder becomes its second output.
Merge consumes at least two inputs.

```bash
./target/release/wallet sign-withdraw --qcash 100 --expiry HEIGHT --cash-dir cash
./target/release/wallet qcash-split --file cash/FILE.QCash --qcash 60 --cash-dir cash
./target/release/wallet qcash-merge --file cash/A.QCash --file cash/B.QCash --cash-dir cash
./target/release/wallet qcash-redeem --file cash/FILE.QCash --to ADDRESS --amount 40 --cash-dir cash
```

The wallet automatically adds a `BlockMiner` output paying `1 paqs` per
canonical transaction byte. There is no manual fee prompt or `--miner` fee
option. For QCash redeem, split, and merge, this fee is deducted from the
QCash value; ordinary spend and withdraw select enough XPQ input value for it.

Output bearer files are saved before submission so private signing material
cannot be lost. Keep every input file until canonical confirmation; never
print, upload, or share `.QCash` contents. Keep plain HTTP RPC on loopback or a
trusted private network.

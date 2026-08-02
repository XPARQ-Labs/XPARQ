# QCash

QCash converts account XPQ into bearer files backed by authenticated QCash
UTXOs:

```text
account XPQ --withdraw--> QCash bearer UTXO
QCash bearer UTXO --redeem--> account XPQ
```

{% hint style="danger" %}
Anyone who controls an unredeemed `.XPQ` file controls its value. Copying the file
copies the ability to redeem it. Treat it like physical cash.
{% endhint %}

## Withdraw

```bash
cargo run --release --bin wallet-cli -- \
  cash withdraw 100 \
  --wallet wallets/mainnet.json \
  --out cash/
```

Supported denominations include:

```text
1, 2, 5, 10, 20, 50, 100, 500, 1000, 1000000 XPQ
```

Cash file names use this form:

```text
<denomination>_<short_coin_id>.XPQ
```

The file is created immediately so its redeem secret is not lost. Ledger
state still determines whether it is pending, redeemable, or redeemed.

## Inspect and synchronize

```bash
cargo run --bin wallet-cli -- cash list cash/
cargo run --bin wallet-cli -- cash sync cash/
cargo run --bin wallet-cli -- \
  cash track 100_C91E1B3A98CDB3A8.XPQ
```

## Redeem

Use the wallet's `cash redeem` command or interactive QCash menu to consume a
bearer file and credit its value to an account. A withdrawal included at
height `H` can be redeemed starting at `H + 1`. The resulting account credit
follows the normal two-block confirmation rule.

## Safe transfer

Before accepting a QCash file:

1. obtain it through a protected channel;
2. verify the file and its coin status with your own node;
3. redeem it promptly when final settlement is required;
4. do not assume deletion by the sender proves that no copy remains.

Back up QCash separately from wallet JSON files.

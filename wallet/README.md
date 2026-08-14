# XPARQ Wallet

`wallet/` contains two related products:

- the `wallet` reusable Rust library for wallet key material and files;
- the `wallet` command-line executable for accounts, payments, QCash, proofs,
  explorer queries, and protocol events.

The wallet does not embed a node or open the node database. It communicates
with `node` over HTTP RPC.

## Build and start

```bash
cargo build --release -p wallet
./target/release/wallet
```

Running without arguments opens the interactive menu. Direct commands remain
available for scripting:

```bash
./target/release/wallet --help
./target/release/wallet new wallet.json --words 24
./target/release/wallet import imported.json
./target/release/wallet balance
./target/release/wallet stats
./target/release/wallet address-stats
./target/release/wallet hashrate
./target/release/wallet send ADDRESS AMOUNT_XPQ
./target/release/wallet cash list cash
./target/release/wallet proof status
```

## Wallet identity and authorization

A wallet derives one signing key from the recovery mnemonic and wallet
password. The stored address is bound to that public key, so restoring the
same address requires both the same mnemonic and the same wallet password.
The signing secret key is derived only when needed and is never stored in the
wallet file.

Mnemonic and wallet-password prompts disable terminal echo. If the
terminal cannot be placed in hidden-input mode, the wallet fails closed rather
than echoing secrets. `wallet.json` contains the recovery mnemonic in plaintext
and is therefore highly sensitive. Keep backups offline and never commit wallet
files to Git. A mining node must use only the public payout address, not this
file.

The wallet password is free-form text, not the mnemonic word count. For
example, entering `12` means the literal password `12`; it does not select a
12-word mnemonic. The password participates in signing-key derivation and does
not encrypt the plaintext mnemonic currently stored in `wallet.json`.

## Shared configuration and RPC

The wallet reads `network` and prefers `rpc_addr_ipv4`, then `rpc_addr_ipv6`, from the same generated configuration
used by the node:

```text
mainnet   data/mainnet/config.json     fallback RPC 127.0.0.1:6666
testnet   data/testnet/config.json     fallback RPC 127.0.0.1:16666
devnet    data/devnet/config.json      fallback RPC 127.0.0.1:26666
```

It ignores node-only P2P, mining, admin, and secret fields. RPC selection
precedence is `--rpc`, `XPARQ_RPC_ADDR`, matching shared config, then the
compiled loopback fallback. `XPARQ_CONFIG` selects a custom shared config for
both binaries.

The wallet currently uses plain HTTP. Keep it on the same trusted machine or a
trusted private network; do not expose an unencrypted wallet RPC workflow to
the public internet.

## Payments and balance

Balance is derived from mature, unspent owned-XPQ outputs. The node's draft
endpoint selects inputs and deterministic change. A normal paid transfer can
contain a recipient output, change back to the sender, and an ordinary
`BlockMiner` output used as the miner payment. Core has no separate fee field.
Standard nodes apply the same configured per-vbyte relay rate to every
transaction family. Operators may set that local rate to zero.

Use `balance [address]` for the summarized balance view. Account/explorer RPC
responses expose the underlying UTXO details needed to audit that total.

## QCash

Withdrawal creates bearer files named with the flexible XPQ amount and full coin ID:

```text
100XPQ_<64_HEX_COIN_ID>.QCash
29.9XPQ_<64_HEX_COIN_ID>.QCash
```

The file contains a private opening secret. Anyone who obtains a valid,
unredeemed file can redeem it, so protect it like physical cash. The ledger
stores only the corresponding unredeemed QCash UTXO; successful redemption
consumes and removes it from the active set. The ledger never stores the bearer
secret. Explorer history can still report the withdrawal and redemption.
Redeem uses an address output plus an optional `BlockMiner` output. Automatic mode
deducts the recommended miner payment from the bearer amount. Withdraw pays
its miner output from the selected on-chain XPQ inputs. The same rate per
virtual byte applies to transfers, withdrawals, full and partial redeems, and
splits. A redeem sent directly to somebody else's wallet is therefore not a
lower-rate alternative to an ordinary on-chain transfer; it is cheaper only if
its actual serialized virtual size is smaller.
Supplying `--amount` performs a partial redeem: the requested value becomes an
owned XPQ output and the remainder becomes a new QCash file. `cash split`
creates multiple independently redeemable bearer files. Each operation is one
transaction with at most one miner output. Generated files are removed if the
node rejects the transaction, while the source bearer file remains available
locally and its spendability is determined by canonical chain state.

Useful commands are:

```bash
./target/release/wallet cash withdraw AMOUNT_XPQ --fee auto --out cash
./target/release/wallet cash inspect cash/100XPQ_<COIN_ID>.QCash
./target/release/wallet cash redeem cash/100XPQ_<COIN_ID>.QCash --to ADDRESS --fee auto
./target/release/wallet cash redeem cash/100XPQ_<COIN_ID>.QCash --to ADDRESS --amount 39 --fee 1 --out cash
./target/release/wallet cash split cash/100XPQ_<COIN_ID>.QCash --amounts 50,29.9 --fee 1 --out cash
./target/release/wallet cash track 100XPQ_<COIN_ID>.QCash
./target/release/wallet cash list cash
./target/release/wallet cash backup cash backup-cash
./target/release/wallet cash recover backup-cash recovered-cash
```

QCash file names must use `.QCash` and the full coin ID. Backup and recovery
operate on QCash bearer files; they do not recreate a missing bearer secret
from the ledger.

Event explorer reports partial redeems as `qcash_redeemed`, including the XPQ
recipient amount and total `qcash_change_amount`. Pure splits use
`qcash_split`.

## Trusted proofs and automatic reorganization recovery

`wallet proof account`, `wallet proof qcash`, and `wallet proof status` verify
state against authenticated header checkpoints saved beside the wallet as
`<wallet-path>.checkpoint`. When a reorganization disconnects a transaction,
the node durably journals the original signed transaction and automatically
revalidates it into the mempool. No wallet command, proof bundle, bearer file,
or second signature is needed for this retry.

## Timestamped diagnostics

Wallet result output, including JSON intended for scripts, remains stable on
standard output. Warnings and errors are written to standard error with a UTC
RFC 3339 timestamp, severity, and `WALLET` component label.

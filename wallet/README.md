# XPARQ Wallet

`wallet/` contains two related products:

- the `wallet` reusable Rust library for wallet key material and files;
- the `wallet` command-line executable for accounts, payments, QCash, proofs,
  explorer queries, protocol events, and rollback recovery.

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

A wallet contains mnemonic-derived owner keys and a separate authorization
key derived from its authorization password. The stored address is bound to
both public keys. Entering a wrong authorization password fails the operation;
it does not replace or reinitialize the wallet's authorization identity.

Mnemonic and authorization-password prompts disable terminal echo. If the
terminal cannot be placed in hidden-input mode, the wallet fails closed rather
than echoing secrets. `wallet.json`, its mnemonic, its owner secret, and the authorization password
are sensitive. Keep backups offline and never commit wallet files to Git. A
mining node needs only the public payout address, not this file.

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

Use `balance [address]` for the summarized balance view. Account/explorer RPC
responses expose the underlying UTXO details needed to audit that total.

## QCash

Withdrawal creates bearer files named with the denomination and full coin ID:

```text
100XPQ_<64_HEX_COIN_ID>.QCash
```

The file contains a private opening secret. Anyone who obtains a valid,
unredeemed file can redeem it, so protect it like physical cash. The ledger
stores only the corresponding unredeemed QCash UTXO; successful redemption
consumes and removes it from the active set. The ledger never stores the bearer
secret. Explorer history can still report the withdrawal and redemption.
Redeem uses an address output plus an optional `BlockMiner` output. Automatic
mode deducts the recommended miner payment from the bearer denomination; core
only validates output value conservation and has no dedicated fee field.

Useful commands are:

```bash
./target/release/wallet cash withdraw AMOUNT_XPQ --out cash
./target/release/wallet cash inspect cash/100XPQ_<COIN_ID>.QCash
./target/release/wallet cash redeem cash/100XPQ_<COIN_ID>.QCash --to ADDRESS --fee auto
./target/release/wallet cash track 100XPQ_<COIN_ID>.QCash
./target/release/wallet cash list cash
./target/release/wallet cash backup cash backup-cash
./target/release/wallet cash recover backup-cash recovered-cash
```

QCash file names must use `.QCash` and the full coin ID. Backup and recovery
operate on QCash bearer files; they do not recreate a missing bearer secret
from the ledger.

## Trusted proofs and rollback recovery

`wallet proof account`, `wallet proof qcash`, and `wallet proof status` verify
state against authenticated header checkpoints saved beside the wallet as
`<wallet-path>.checkpoint`. Public wallet rollback commands can list, inspect,
and locally verify node-reported recovery proofs. Retrying a rollback issue is
an authenticated node-admin operation and is intentionally not exposed by the
wallet CLI.

## Timestamped diagnostics

Wallet result output, including JSON intended for scripts, remains stable on
standard output. Warnings and errors are written to standard error with a UTC
RFC 3339 timestamp, severity, and `WALLET` component label.

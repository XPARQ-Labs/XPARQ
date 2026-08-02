# Creating a wallet

Wallet files are plaintext JSON and contain the primary secret key. Protect
them as secret material and never commit them to source control.

## Create

```bash
cargo run --release --bin wallet-cli \
  --no-default-features --features mainnet -- \
  new wallets/mainnet.json
```

To display the generated secret key:

```bash
cargo run --release --bin wallet-cli -- \
  new wallet.json --show-secret
```

Only use `--show-secret` in a private terminal that is not logged or shared.

## Import

Import an existing Paqus mnemonic:

```bash
cargo run --release --bin wallet-cli -- \
  import wallet.json --mnemonic "word1 word2 ... word12"
```

Avoid placing a real mnemonic directly in shell history. Use the interactive
flow where available.

## Address derivation

```bash
cargo run --release --bin wallet-cli -- \
  address <secret-key-hex>
```

## Interactive menu

Run the wallet with no command:

```bash
cargo run --release --bin wallet-cli
```

The authorization password is processed with Argon2id. Prefer the hidden
interactive prompt over command-line password flags, which may be visible in
shell history and process listings.

## Backups

Keep multiple encrypted offline backups and test recovery before the wallet
holds value. A blockchain database backup is not a wallet backup.

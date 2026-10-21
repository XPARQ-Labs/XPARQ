# Legacy Wallet Salt Migration

This guide covers moving XPQ from a legacy signature account whose account salt
is 32 bytes to an account using the current 16-byte wallet salt. It describes an
on-chain XPQ transfer; it does not convert old wallet-file formats or move
program assets.

## Salt formats

- Current wallet accounts use a 16-byte salt, written as 32 hexadecimal
  characters. Newly created wallets default to 16 zero bytes.
- A legacy account uses a 32-byte salt, written as 64 hexadecimal characters.
  The wallet accepts this salt only as the source signer for a single native
  XPQ transfer. It cannot be added or selected as a regular wallet account, or
  used to create a new Program ID through the normal account menu.
- Program IDs remain 32 bytes and are displayed as 64 hexadecimal characters.
  A salt length and a Program ID length are different things.

The legacy salt is still needed to derive the old source Program ID and sign the
spend. Preserve it with the wallet recovery material so you can identify and
authorize that account again if needed.

## Requirements

You need:

1. A wallet file for the same mnemonic and signature scheme that controlled the
   legacy account.
2. The legacy 32-byte salt recorded in that wallet file's `account_salts` list.
   The transfer-only compatibility loader checks this before signing.
3. The full 64-character hexadecimal legacy salt.
4. A destination Program ID for an account you control, normally one created
   with a 16-byte salt, and access to a running node RPC endpoint.

Reserved legacy coins are not available to this transfer. The destination is
treated as a Program ID; the wallet checks its format but cannot verify that
you control it. Verify the destination carefully before broadcasting.

## Interactive migration

Start the wallet without a subcommand and choose **13. Migrate Legacy 32-byte
Account**. Enter the wallet file, legacy salt, destination Program ID, and RPC
address when prompted.

The wallet prepares one XPQ transfer using all currently available legacy XPQ
UTXOs. It displays the source Program ID, available balance, destination amount,
miner fee, and protocol burn. The destination amount is the available balance
after the fee and protocol burn are deducted. No change output is created.

Review the destination and amounts. Type `MIGRATE` exactly to broadcast the
transaction; any other response cancels it. The transfer is signed with the
legacy salt, but that salt is not installed as an account or saved by this
operation. The receiving account uses its own 16-byte salt and Program ID.

If some coins are reserved, they remain at the legacy Program ID until they are
available. Run the migration again if those coins later become spendable.
Program assets are not included in this XPQ migration.

## Command-line transfer

For a partial transfer, use the regular native XPQ send command with the legacy
salt:

```sh
wallet sign-spend \
  --legacy-salt LEGACY_SALT_HEX64 \
  --to DESTINATION_PROGRAM_ID \
  --amount 1.25 \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

The CLI calculates the miner fee and protocol burn. `--legacy-salt` is limited
to this native XPQ transfer path; other operations use a regular 16-byte wallet
account. `--offline` prints a signed transaction instead of submitting it, but
RPC is still needed for input selection and fee calculation.

## Related documentation

- [Wallet usage](wallet/README.md)
- [Program identity and ownership](docs/OWNERSHIP.md)
- [Signature schemes](docs/SIGNATURE_SCHEMES.md)

# Coin vault extension

[`coin-vault.wat`](coin-vault.wat) is a minimal ABI v3 extension that can hold
native XPQ coin and send its own coin to an account address or another
extension. Receiving requires no guest callback: a normal coin output owned by
the vault's `ExtensionHash` becomes part of its ledger balance.

Build and deploy it:

```bash
wat2wasm dev-tools/examples/coin-vault.wat -o coin-vault.wasm
cargo run -p wallet -- wasm-deploy \
  --name example.coin-vault \
  --wasm coin-vault.wasm \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

After its activation delay, deposit coin using the printed extension ID:

```bash
cargo run -p wallet -- sign-spend \
  --extension extension:EXTENSION_HASH \
  --amount 10 \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

Check that the deposit entered the vault:

```bash
cargo run -p wallet -- wasm-info \
  --extension extension:EXTENSION_HASH \
  --rpc 127.0.0.1:6666
```

The `coin_balance` field is the vault's total balance in zeno and
`coin_utxo_count` is the number of coin outputs it owns. The example vault does
not track balances per depositor.

Calls use a small canonical binary payload:

| Opcode | Recipient | Payload |
|---|---|---|
| `01` | Address | `01 || address[20] || amount_le_u64` |
| `02` | Extension | `02 || extension_hash[32] || amount_le_u64` |

For example, send 9 zeno to the 20-byte address consisting entirely of `21`:

```bash
cargo run -p wallet -- wasm-call \
  --extension extension:EXTENSION_HASH \
  --payload-hex 0121212121212121212121212121212121212121210900000000000000 \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

The amount is expressed in zeno and encoded as an unsigned little-endian
64-bit integer. The guest rejects unknown opcodes, incorrect payload lengths,
and zero amounts. The ledger rejects a call when the vault balance is
insufficient and rolls back all extension state, effects, and fees atomically.

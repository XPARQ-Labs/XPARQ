# Balances and transfers

## Select the node

The wallet reads the RPC address from `PAQUS_RPC_ADDR`:

```bash
export PAQUS_RPC_ADDR=127.0.0.1:6666
```

Use the node's configured RPC listener if it differs from the mainnet default.

## Balance

```bash
cargo run --release --bin wallet-cli -- \
  balance --wallet wallets/mainnet.json
```

The wallet separates on-chain available, incoming, outgoing, locked, and
off-chain cash balances. It also shows the current AccountStatement and draft
basis used for the next signed transaction. A newly included credit is not
immediately mature.

Additional views:

```bash
cargo run --release --bin wallet-cli -- stats
cargo run --release --bin wallet-cli -- hashrate
cargo run --release --bin wallet-cli -- \
  address-stats --wallet wallets/mainnet.json
```

## Send XPQ

Send to one recipient:

```bash
cargo run --release --bin wallet-cli -- \
  send P1RECIPIENT 10 \
  --wallet wallets/mainnet.json
```

Send one atomic multi-output transaction:

```bash
cargo run --release --bin wallet-cli -- \
  send \
  --output P1RECIPIENT_A:10 \
  --output P1RECIPIENT_B:25.5 \
  --wallet wallets/mainnet.json \
  --submit
```

A transfer supports 1–64 unique recipients. All outputs succeed together or
the complete transaction is rejected.

Fees are local node/miner policy, not a consensus field. The wallet can ask
the node for the current draft basis and fee-rate guidance before building a
transaction. Fee rates are expressed in `paqus/byte`.

## Units

```text
1 XPQ = 1,000,000 paqus
```

## Reorganizations

Inspect recovery records:

```bash
cargo run --bin wallet-cli -- rollback list P1ADDRESS
cargo run --bin wallet-cli -- rollback show ISSUE_ID
cargo run --bin wallet-cli -- rollback verify ISSUE_ID
cargo run --bin wallet-cli -- rollback retry ISSUE_ID
```

Verification checks transaction authorization proofs, header proof of work,
ancestry, fork choice, and the canonical tip before retrying the original
signed transaction.

# Quick start

Run these commands from the project root.

## 1. Create a mainnet wallet

```bash
cargo run --release --bin wallet-cli \
  --no-default-features --features mainnet -- \
  new wallets/mainnet.json
```

The CLI asks for an authorization password through a hidden prompt.

## 2. Start a local node

```bash
cargo run --release --bin paqus-node \
  --no-default-features --features mainnet -- \
  node run data/mainnet \
  --network mainnet \
  --wallet wallets/mainnet.json \
  --mine \
  --mine-attempts 0 \
  --mine-interval-secs 10
```

Press `Ctrl+C` for a clean shutdown.

## 3. Check node health

In another terminal:

```bash
curl http://127.0.0.1:6666/health
curl http://127.0.0.1:6666/status
curl http://127.0.0.1:6666/chain
```

## 4. Check the wallet

```bash
PAQUS_RPC_ADDR=127.0.0.1:6666 \
cargo run --release --bin wallet-cli \
  --no-default-features --features mainnet -- \
  balance --wallet wallets/mainnet.json
```

Mainnet has no genesis premine. Newly mined subsidy cannot be spent until its
50-block maturity period has passed.
